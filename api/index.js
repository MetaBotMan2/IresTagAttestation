const express = require('express');
const crypto = require('crypto');

const app = express();

app.use(express.json());
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

const CONFIG = {
    DISCORD_WEBHOOK_SUCCESS: 'https://discord.com/api/webhooks/1573109880573792286/jRjcpzMKYyKqmBRSqq8VYQhqCZMwfBrj_0pKeT4EJ8iGnC1tQRH4b3ik961y1ebCI0Vy',
    DISCORD_WEBHOOK_FAILURE: 'https://discord.com/api/webhooks/1573132658286788759/8D4x1nzvQK7GKHXpV8ihJDm-YkQnJaUYglK2IlBKn3hJu5onRtRBonMhxUqWHyMDFO8a',
    META_APP_ID: '1351421471398875',
    META_APP_SECRET: 'f8060178b29baa6e9676eb485ce51773',
    CHALLENGE_EXPIRY_MS: 300000,
    MAX_PENDING_DAYS: 7
};

const challenges = new Map();
const verifiedUsers = new Set();

async function sendDiscordWebhook(webhookUrl, content) {
    if (!webhookUrl || webhookUrl.includes('YOUR_')) return;
    
    try {
        await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                embeds: [{
                    title: content.title,
                    description: content.description,
                    color: content.color || 5814783,
                    fields: content.fields || [],
                    timestamp: new Date().toISOString(),
                    footer: { text: 'Device Verification System by ires' }
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
            orgScopedId: 'N/A',
            deviceIntegrityState: 'N/A',
            appIntegrityState: 'N/A',
            securityUpdateDays: 0
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
                orgScopedId: userInfo.orgScopedId,
                deviceIntegrityState: 'N/A',
                appIntegrityState: 'N/A',
                securityUpdateDays: 0
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
                orgScopedId: userInfo.orgScopedId,
                deviceIntegrityState: 'N/A',
                appIntegrityState: 'N/A',
                securityUpdateDays: 0
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

        const deviceIntegrityState = deviceState?.device_integrity || 'N/A';
        const appIntegrityState = appState?.app_integrity || 'N/A';

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

        const securityUpdatePendingDays = deviceState?.security_update_pending_days || 0;
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
            deviceIntegrityState: deviceIntegrityState,
            appIntegrityState: appIntegrityState,
            securityUpdatePending: securityUpdatePending,
            securityUpdateDays: securityUpdatePendingDays,
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
            orgScopedId: 'N/A',
            deviceIntegrityState: 'N/A',
            appIntegrityState: 'N/A',
            securityUpdateDays: 0
        };
    }
}

app.post('/api/auth/challenge', async (req, res) => {
    try {
        const { UserId, Nonce } = req.body;

        if (!UserId || !Nonce) {
            await sendDiscordWebhook(CONFIG.DISCORD_WEBHOOK_FAILURE, {
                title: '❌ Challenge Request Failed',
                description: 'Missing required fields',
                color: 15158332,
                fields: [
                    { name: 'User ID', value: UserId || 'N/A', inline: true },
                    { name: 'Nonce', value: Nonce ? 'Present' : 'Missing', inline: true }
                ]
            });
            return res.status(400).json({ error: 'Missing UserId or Nonce' });
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

        return res.status(200).json({ challenge_nonce: challengeNonce });
    } catch (error) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/complete', async (req, res) => {
    try {
        const { UserId, AttestationToken } = req.body;

        if (!UserId || !AttestationToken) {
            await sendDiscordWebhook(CONFIG.DISCORD_WEBHOOK_FAILURE, {
                title: '❌ Verification Failed',
                description: 'Missing required fields',
                color: 15158332,
                fields: [
                    { name: 'User ID', value: UserId || 'N/A', inline: true },
                    { name: 'Token', value: AttestationToken ? 'Present' : 'Missing', inline: true }
                ]
            });
            return res.status(400).json({ error: 'Missing UserId or AttestationToken' });
        }

        const challengeData = challenges.get(UserId);
        if (!challengeData) {
            await sendDiscordWebhook(CONFIG.DISCORD_WEBHOOK_FAILURE, {
                title: '❌ Verification Failed',
                description: 'No active challenge found for user',
                color: 15158332,
                fields: [
                    { name: 'User ID', value: UserId, inline: true },
                    { name: 'Reason', value: 'Challenge expired or never created', inline: true }
                ]
            });
            return res.status(400).json({ error: 'No active challenge found' });
        }

        const verification = await verifyMetaIntegrity(
            UserId,
            AttestationToken,
            challengeData.challengeNonce
        );

        challenges.delete(UserId);

        if (verification.valid) {
            verifiedUsers.add(UserId);
            
            await sendDiscordWebhook(CONFIG.DISCORD_WEBHOOK_SUCCESS, {
                title: '✅ Verification Successful',
                description: 'User successfully verified with all security checks passed',
                color: 5763719,
                fields: [
                    { name: 'User ID', value: UserId, inline: true },
                    { name: 'Oculus Username', value: verification.username, inline: true },
                    { name: 'Org-Scoped ID', value: verification.orgScopedId, inline: true },
                    { name: 'Device Integrity State', value: verification.deviceIntegrityState, inline: true },
                    { name: 'App Integrity State', value: verification.appIntegrityState, inline: true },
                    { name: 'Security Update Days', value: `${verification.securityUpdateDays} days`, inline: true },
                    { name: 'Device Check', value: verification.deviceIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
                    { name: 'App Check', value: verification.appIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
                    { name: 'Security Updates', value: verification.securityUpdatePending ? '❌ PENDING' : '✅ UP TO DATE', inline: true },
                    { name: 'Timestamp', value: new Date().toLocaleString(), inline: false }
                ]
            });
            
            return res.status(200).json({ 
                success: true,
                deviceIntegrity: verification.deviceIntegrity,
                appIntegrity: verification.appIntegrity,
                securityUpdatePending: verification.securityUpdatePending
            });
        } else {
            await sendDiscordWebhook(CONFIG.DISCORD_WEBHOOK_FAILURE, {
                title: '❌ Verification Failed',
                description: 'Security checks failed',
                color: 15158332,
                fields: [
                    { name: 'User ID', value: UserId, inline: true },
                    { name: 'Oculus Username', value: verification.username, inline: true },
                    { name: 'Org-Scoped ID', value: verification.orgScopedId, inline: true },
                    { name: 'Device Integrity State', value: verification.deviceIntegrityState, inline: true },
                    { name: 'App Integrity State', value: verification.appIntegrityState, inline: true },
                    { name: 'Security Update Days', value: `${verification.securityUpdateDays} days`, inline: true },
                    { name: 'Device Check', value: verification.deviceIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
                    { name: 'App Check', value: verification.appIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
                    { name: 'Security Updates', value: verification.securityUpdatePending ? '❌ PENDING' : '✅ UP TO DATE', inline: true },
                    { name: 'Failure Reason', value: verification.reason || 'Unknown', inline: false },
                    { name: 'Details', value: verification.details || verification.error || 'N/A', inline: false }
                ]
            });
            
            return res.status(403).json({ 
                error: 'Verification failed',
                reason: verification.reason,
                deviceIntegrity: verification.deviceIntegrity,
                appIntegrity: verification.appIntegrity,
                securityUpdatePending: verification.securityUpdatePending,
                securityUpdateDays: verification.securityUpdateDays
            });
        }
    } catch (error) {
        await sendDiscordWebhook(CONFIG.DISCORD_WEBHOOK_FAILURE, {
            title: '⚠️ Server Error',
            description: 'Unexpected error occurred',
            color: 15105570,
            fields: [
                { name: 'Error', value: error.message, inline: false },
                { name: 'Stack', value: error.stack?.substring(0, 1000) || 'N/A', inline: false }
            ]
        });
        
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/status', async (req, res) => {
    try {
        const { UserId } = req.body;
        
        if (!UserId) {
            return res.status(400).json({ error: 'Missing UserId' });
        }
        
        const isVerified = verifiedUsers.has(UserId);
        
        return res.status(200).json({
            verified: isVerified,
            userId: UserId
        });
    } catch (error) {
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/test-fail', async (req, res) => {
    const testScenarios = {
        device_not_trusted: {
            username: 'TestUser_DeviceNotTrusted',
            orgScopedId: '1234567890',
            deviceIntegrity: false,
            appIntegrity: true,
            deviceIntegrityState: 'NotTrusted',
            appIntegrityState: 'Recognized',
            securityUpdatePending: false,
            securityUpdateDays: 0,
            reason: 'Device is NotTrusted'
        },
        device_basic: {
            username: 'TestUser_BasicIntegrity',
            orgScopedId: '0987654321',
            deviceIntegrity: false,
            appIntegrity: true,
            deviceIntegrityState: 'Basic',
            appIntegrityState: 'Recognized',
            securityUpdatePending: false,
            securityUpdateDays: 2,
            reason: 'Device integrity is Basic'
        },
        app_unrecognized: {
            username: 'TestUser_UnrecognizedApp',
            orgScopedId: '1122334455',
            deviceIntegrity: true,
            appIntegrity: false,
            deviceIntegrityState: 'Strong',
            appIntegrityState: 'Unrecognized',
            securityUpdatePending: false,
            securityUpdateDays: 0,
            reason: 'App version is unrecognized'
        },
        security_pending: {
            username: 'TestUser_SecurityPending',
            orgScopedId: '5544332211',
            deviceIntegrity: true,
            appIntegrity: true,
            deviceIntegrityState: 'Strong',
            appIntegrityState: 'Recognized',
            securityUpdatePending: true,
            securityUpdateDays: 45,
            reason: 'Security updates pending for 45 days'
        },
        all_fail: {
            username: 'TestUser_AllFailed',
            orgScopedId: '9999999999',
            deviceIntegrity: false,
            appIntegrity: false,
            deviceIntegrityState: 'NotTrusted',
            appIntegrityState: 'Unrecognized',
            securityUpdatePending: true,
            securityUpdateDays: 90,
            reason: 'Device is NotTrusted, App version is unrecognized, Security updates pending for 90 days'
        }
    };

    const scenario = req.body.scenario || 'all_fail';
    const testData = testScenarios[scenario] || testScenarios.all_fail;
    const testUserId = req.body.UserId || '1234567890';

    await sendDiscordWebhook(CONFIG.DISCORD_WEBHOOK_FAILURE, {
        title: '❌ Test Verification Failed',
        description: `Testing failure scenario: ${scenario}`,
        color: 15158332,
        fields: [
            { name: 'User ID', value: testUserId, inline: true },
            { name: 'Oculus Username', value: testData.username, inline: true },
            { name: 'Org-Scoped ID', value: testData.orgScopedId, inline: true },
            { name: 'Device Integrity State', value: testData.deviceIntegrityState, inline: true },
            { name: 'App Integrity State', value: testData.appIntegrityState, inline: true },
            { name: 'Security Update Days', value: `${testData.securityUpdateDays} days`, inline: true },
            { name: 'Device Check', value: testData.deviceIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
            { name: 'App Check', value: testData.appIntegrity ? '✅ PASS' : '❌ FAIL', inline: true },
            { name: 'Security Updates', value: testData.securityUpdatePending ? '❌ PENDING' : '✅ UP TO DATE', inline: true },
            { name: 'Failure Reason', value: testData.reason, inline: false },
            { name: 'Test Scenario', value: scenario, inline: false }
        ]
    });

    return res.status(200).json({
        test: true,
        scenario: scenario,
        webhookSent: true,
        testData: testData
    });
});

app.get('/api/health', (req, res) => {
    res.status(200).json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        service: 'Device Verification API'
    });
});

module.exports = app;
