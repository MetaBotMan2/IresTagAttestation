const crypto = require('crypto');

const CONFIG = {
    DISCORD_WEBHOOK_URL: 'https://discord.com/api/webhooks/1573109880573792286/jRjcpzMKYyKqmBRSqq8VYQhqCZMwfBrj_0pKeT4EJ8iGnC1tQRH4b3ik961y1ebCI0Vy',
    META_APP_ID: '1351421471398875',
    META_APP_SECRET: 'f8060178b29baa6e9676eb485ce51773',
    CHALLENGE_EXPIRY_MS: 300000,
    MAX_PENDING_DAYS: 7
};

const challenges = new Map();
const verifiedUsers = new Set();

async function sendDiscordWebhook(content) {
    if (!CONFIG.DISCORD_WEBHOOK_URL || CONFIG.DISCORD_WEBHOOK_URL.includes('YOUR_WEBHOOK')) return;
    
    try {
        await fetch(CONFIG.DISCORD_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                embeds: [{
                    title: content.title,
                    description: content.description,
                    color: content.color || 5814783,
                    fields: content.fields || [],
                    timestamp: new Date().toISOString(),
                    footer: { text: 'Device Verification System' }
                }]
            })
        });
    } catch (error) {
        console.error('Discord webhook failed:', error);
    }
}

async function getUserInfo(userId) {
    if (!CONFIG.META_APP_ID || CONFIG.META_APP_ID.includes('YOUR_META')) {
        return { username: 'N/A', orgScopedId: 'N/A' };
    }

    try {
        const response = await fetch(`https://graph.oculus.com/${userId}?fields=alias,org_scoped_id&access_token=${CONFIG.META_APP_ID}|${CONFIG.META_APP_SECRET}`);
        
        if (!response.ok) {
            return { username: 'N/A', orgScopedId: 'N/A' };
        }

        const data = await response.json();
        return {
            username: data.alias || 'N/A',
            orgScopedId: data.org_scoped_id || 'N/A'
        };
    } catch (error) {
        return { username: 'N/A', orgScopedId: 'N/A' };
    }
}

async function verifyMetaIntegrity(userId, attestationToken, challengeNonce) {
    if (!CONFIG.META_APP_ID || CONFIG.META_APP_ID.includes('YOUR_META')) {
        return { 
            valid: false, 
            reason: 'Meta credentials not configured',
            securityUpdatePending: false,
            deviceIntegrity: false,
            appIntegrity: false,
            username: 'N/A',
            orgScopedId: 'N/A'
        };
    }

    try {
        const userInfo = await getUserInfo(userId);

        const response = await fetch('https://graph.oculus.com/integrity_token_verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `OC|${CONFIG.META_APP_ID}|${CONFIG.META_APP_SECRET}`
            },
            body: JSON.stringify({
                integrity_token: attestationToken,
                nonce: challengeNonce,
                user_id: userId
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            return { 
                valid: false, 
                reason: `Meta API error: ${response.status}`,
                details: errorText,
                securityUpdatePending: false,
                deviceIntegrity: false,
                appIntegrity: false,
                username: userInfo.username,
                orgScopedId: userInfo.orgScopedId
            };
        }

        let result = await response.json();
        
        let data = result.data;
        if (Array.isArray(data)) {
            data = data[0];
        }

        const message = data?.message;
        if (message !== 'success') {
            return {
                valid: false,
                reason: `Verification message: ${message || 'Unknown'}`,
                securityUpdatePending: false,
                deviceIntegrity: false,
                appIntegrity: false,
                username: userInfo.username,
                orgScopedId: userInfo.orgScopedId
            };
        }

        let claimsPayload = null;
        if (typeof data.claims === 'string') {
            try {
                claimsPayload = JSON.parse(data.claims);
            } catch (e) {
                claimsPayload = data.claims;
            }
        } else {
            claimsPayload = data.claims;
        }

        const deviceState = claimsPayload?.device_state;
        const appState = claimsPayload?.app_state;

        const deviceIntegrityState = deviceState?.device_integrity;
        const appIntegrityState = appState?.app_integrity;

        let deviceIntegrity = true;
        let deviceFailReason = null;

        if (deviceIntegrityState === 'NotTrusted') {
            deviceIntegrity = false;
            deviceFailReason = 'Device is NotTrusted';
        } else if (deviceIntegrityState === 'Basic') {
            deviceIntegrity = false;
            deviceFailReason = 'Device integrity is Basic';
        }

        let appIntegrity = true;
        let appFailReason = null;

        if (appIntegrityState === 'Unrecognized') {
            appIntegrity = false;
            appFailReason = 'App version is unrecognized';
        }

        const securityUpdatePendingDays = deviceState?.security_update_pending_days;
        let securityUpdatePending = false;
        let securityUpdateFailReason = null;

        if (securityUpdatePendingDays !== undefined && securityUpdatePendingDays > CONFIG.MAX_PENDING_DAYS) {
            securityUpdatePending = true;
            securityUpdateFailReason = `Security updates pending for ${securityUpdatePendingDays} days`;
        }

        const allChecksPass = deviceIntegrity && appIntegrity && !securityUpdatePending;

        let failureReasons = [];
        if (deviceFailReason) failureReasons.push(deviceFailReason);
        if (appFailReason) failureReasons.push(appFailReason);
        if (securityUpdateFailReason) failureReasons.push(securityUpdateFailReason);

        return { 
            valid: allChecksPass,
            deviceIntegrity: deviceIntegrity,
            appIntegrity: appIntegrity,
            appIntegrityVerdict: appIntegrityState || 'N/A',
            deviceIntegrityVerdict: deviceIntegrityState || 'N/A',
            securityUpdatePending: securityUpdatePending,
            securityUpdateDays: securityUpdatePendingDays || 0,
            username: userInfo.username,
            orgScopedId: userInfo.orgScopedId,
            reason: allChecksPass ? 'All checks passed' : failureReasons.join(', '),
            rawData: result
        };
    } catch (error) {
        return { 
            valid: false, 
            reason: 'Meta verification failed',
            error: error.message,
            securityUpdatePending: false,
            deviceIntegrity: false,
            appIntegrity: false,
            username: 'N/A',
            orgScopedId: 'N/A'
        };
    }
}

async function handleChallenge(body) {
    const { UserId, Nonce } = body;

    if (!UserId || !Nonce) {
        await sendDiscordWebhook({
            title: 'Challenge Request Failed',
            description: 'missing required fields',
            color: 15158332,
            fields: [
                { name: 'user id', value: UserId || 'N/A', inline: true },
                { name: 'nonce', value: Nonce ? 'Present' : 'Missing', inline: true }
            ]
        });
        return { 
            status: 400, 
            data: { error: 'Missing UserId or Nonce' } 
        };
    }

    const challengeNonce = crypto.randomBytes(32).toString('hex');
    
    challenges.set(UserId, {
        userNonce: Nonce,
        challengeNonce: challengeNonce,
        timestamp: Date.now()
    });

    setTimeout(() => {
        challenges.delete(UserId);
    }, CONFIG.CHALLENGE_EXPIRY_MS);

    await sendDiscordWebhook({
        title: 'challenge generated',
        description: 'new verification challenge created',
        color: 3447003,
        fields: [
            { name: 'user id', value: UserId, inline: true },
            { name: 'user nonce', value: Nonce.substring(0, 16) + '...', inline: true },
            { name: 'challenge nonce', value: challengeNonce.substring(0, 16) + '...', inline: false },
            { name: 'expiry', value: `${CONFIG.CHALLENGE_EXPIRY_MS / 1000}s`, inline: true }
        ]
    });

    return { 
        status: 200, 
        data: { challenge_nonce: challengeNonce } 
    };
}

async function handleComplete(body) {
    const { UserId, AttestationToken } = body;

    if (!UserId || !AttestationToken) {
        await sendDiscordWebhook({
            title: 'Attestation Failed',
            description: 'missing required fields',
            color: 15158332,
            fields: [
                { name: 'user id', value: UserId || 'N/A', inline: true },
                { name: 'token', value: AttestationToken ? 'Present' : 'missing', inline: true }
            ]
        });
        return { 
            status: 400, 
            data: { error: 'missing user id or attestation token' } 
        };
    }

    const challengeData = challenges.get(UserId);
    if (!challengeData) {
        await sendDiscordWebhook({
            title: '❌ Verification Failed',
            description: 'No active challenge found for user',
            color: 15158332,
            fields: [
                { name: 'User ID', value: UserId, inline: true },
                { name: 'Reason', value: 'Challenge expired or never created', inline: true }
            ]
        });
        return { 
            status: 400, 
            data: { error: 'No active challenge found' } 
        };
    }

    const verification = await verifyMetaIntegrity(
        UserId,
        AttestationToken,
        challengeData.challengeNonce
    );

    challenges.delete(UserId);

    if (verification.valid) {
        verifiedUsers.add(UserId);
        
        await sendDiscordWebhook({
            title: 'Attestation Successful',
            description: 'user successfully verified with all security checks passed',
            color: 5763719,
            fields: [
                { name: 'User ID', value: UserId, inline: true },
                { name: 'Oculus Username', value: verification.username, inline: true },
                { name: 'Org-Scoped ID', value: verification.orgScopedId, inline: true },
                { name: 'Status', value: 'verified', inline: true },
                { name: 'Device Integrity', value: verification.deviceIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
                { name: 'App Integrity', value: verification.appIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
                { name: 'Security Updates', value: verification.securityUpdatePending ? '❌ PENDING' : '✅ UP TO DATE', inline: true },
                { name: 'Pending Days', value: `${verification.securityUpdateDays} days`, inline: true },
                { name: 'Device Verdict', value: verification.deviceIntegrityVerdict || 'N/A', inline: false },
                { name: 'App Verdict', value: verification.appIntegrityVerdict || 'N/A', inline: false },
                { name: 'Timestamp', value: new Date().toLocaleString(), inline: false }
            ]
        });
        
        return { 
            status: 200, 
            data: { 
                success: true,
                deviceIntegrity: verification.deviceIntegrity,
                appIntegrity: verification.appIntegrity,
                securityUpdatePending: verification.securityUpdatePending
            } 
        };
    } else {
        await sendDiscordWebhook({
            title: '❌ Verification Failed',
            description: 'Security checks failed',
            color: 15158332,
            fields: [
                { name: 'User ID', value: UserId, inline: true },
                { name: 'Oculus Username', value: verification.username, inline: true },
                { name: 'Org-Scoped ID', value: verification.orgScopedId, inline: true },
                { name: 'Status', value: '❌ FAILED', inline: true },
                { name: 'Device Integrity', value: verification.deviceIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
                { name: 'App Integrity', value: verification.appIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
                { name: 'Security Updates', value: verification.securityUpdatePending ? '❌ PENDING' : '✅ UP TO DATE', inline: true },
                { name: 'Pending Days', value: `${verification.securityUpdateDays} days`, inline: true },
                { name: 'Device Verdict', value: verification.deviceIntegrityVerdict || 'N/A', inline: false },
                { name: 'App Verdict', value: verification.appIntegrityVerdict || 'N/A', inline: false },
                { name: 'Reason', value: verification.reason || 'Unknown', inline: false },
                { name: 'Details', value: verification.details || verification.error || 'N/A', inline: false }
            ]
        });
        
        return { 
            status: 403, 
            data: { 
                error: 'Verification failed',
                reason: verification.reason,
                deviceIntegrity: verification.deviceIntegrity,
                appIntegrity: verification.appIntegrity,
                securityUpdatePending: verification.securityUpdatePending,
                securityUpdateDays: verification.securityUpdateDays
            } 
        };
    }
}

async function handleStatus(body) {
    const { UserId } = body;
    
    if (!UserId) {
        return {
            status: 400,
            data: { error: 'Missing UserId' }
        };
    }
    
    const isVerified = verifiedUsers.has(UserId);
    
    return {
        status: 200,
        data: {
            verified: isVerified,
            userId: UserId
        }
    };
}

async function handleTestFail(body) {
    const testScenarios = {
        device_not_trusted: {
            username: 'TestUser_DeviceNotTrusted',
            orgScopedId: '1234567890',
            deviceIntegrity: false,
            appIntegrity: true,
            deviceIntegrityVerdict: 'NotTrusted',
            appIntegrityVerdict: 'Recognized',
            securityUpdatePending: false,
            securityUpdateDays: 0,
            reason: 'Device is NotTrusted'
        },
        device_basic: {
            username: 'TestUser_BasicIntegrity',
            orgScopedId: '0987654321',
            deviceIntegrity: false,
            appIntegrity: true,
            deviceIntegrityVerdict: 'Basic',
            appIntegrityVerdict: 'Recognized',
            securityUpdatePending: false,
            securityUpdateDays: 2,
            reason: 'Device integrity is Basic'
        },
        app_unrecognized: {
            username: 'TestUser_UnrecognizedApp',
            orgScopedId: '1122334455',
            deviceIntegrity: true,
            appIntegrity: false,
            deviceIntegrityVerdict: 'Strong',
            appIntegrityVerdict: 'Unrecognized',
            securityUpdatePending: false,
            securityUpdateDays: 0,
            reason: 'App version is unrecognized'
        },
        security_pending: {
            username: 'TestUser_SecurityPending',
            orgScopedId: '5544332211',
            deviceIntegrity: true,
            appIntegrity: true,
            deviceIntegrityVerdict: 'Strong',
            appIntegrityVerdict: 'Recognized',
            securityUpdatePending: true,
            securityUpdateDays: 45,
            reason: 'Security updates pending for 45 days'
        },
        all_fail: {
            username: 'TestUser_AllFailed',
            orgScopedId: '9999999999',
            deviceIntegrity: false,
            appIntegrity: false,
            deviceIntegrityVerdict: 'NotTrusted',
            appIntegrityVerdict: 'Unrecognized',
            securityUpdatePending: true,
            securityUpdateDays: 90,
            reason: 'Device is NotTrusted, App version is unrecognized, Security updates pending for 90 days'
        }
    };

    const scenario = body.scenario || 'all_fail';
    const testData = testScenarios[scenario] || testScenarios.all_fail;
    const testUserId = body.UserId || '1234567890';

    await sendDiscordWebhook({
        title: 'Test Verification Failed',
        description: `Testing failure scenario: ${scenario}`,
        color: 15158332,
        fields: [
            { name: 'User ID', value: testUserId, inline: true },
            { name: 'Oculus Username', value: testData.username, inline: true },
            { name: 'Org Scoped ID', value: testData.orgScopedId, inline: true },
            { name: 'Status', value: '❌ FAILED (TEST)', inline: true },
            { name: 'Device Integrity', value: testData.deviceIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
            { name: 'App Integrity', value: testData.appIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
            { name: 'Security Updates', value: testData.securityUpdatePending ? '❌ PENDING' : '✅ UP TO DATE', inline: true },
            { name: 'Pending Days', value: `${testData.securityUpdateDays} days`, inline: true },
            { name: 'Device Verdict', value: testData.deviceIntegrityVerdict, inline: false },
            { name: 'App Verdict', value: testData.appIntegrityVerdict, inline: false },
            { name: 'Reason', value: testData.reason, inline: false },
            { name: 'Test Scenario', value: scenario, inline: false }
        ]
    });

    return {
        status: 200,
        data: {
            test: true,
            scenario: scenario,
            webhookSent: true,
            testData: testData
        }
    };
}

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const body = req.body;
        const action = body.action || req.url.split('/').pop();

        let result;

        switch (action) {
            case 'challenge':
                result = await handleChallenge(body);
                break;
            case 'complete':
                result = await handleComplete(body);
                break;
            case 'status':
                result = await handleStatus(body);
                break;
            case 'test-fail':
                result = await handleTestFail(body);
                break;
            default:
                result = {
                    status: 400,
                    data: { error: 'Invalid action. Use: challenge, complete, status, or test-fail' }
                };
        }

        return res.status(result.status).json(result.data);
    } catch (error) {
        await sendDiscordWebhook({
            title: 'Server Error',
            description: 'Unexpected error occurred',
            color: 15105570,
            fields: [
                { name: 'Error', value: error.message, inline: false },
                { name: 'Stack', value: error.stack?.substring(0, 1000) || 'N/A', inline: false }
            ]
        });
        
        return res.status(500).json({ error: 'Internal server error' });
    }
};
