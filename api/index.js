const express = require('express');
const fetch = require('node-fetch');
const app = express();
const port = process.env.PORT || 3000;

const APP_ID = '1264796100052780';
const APP_SECRET = 'f5f7690390494c247d52a27692c7ed2c';
const ACCESS_TOKEN = `OC|${APP_ID}|${APP_SECRET}`;

const expectedPackageName = 'com.IresLLC.IresTag';
const expectedCertHash = '35800750f4fb52ce8a45ca8158e021590df93bf1bbfdf74edc503388c065fe11';

const passedWebhook = 'https://discord.com/api/webhooks/1532446842502250678/Pp6GfxBEatb3yAVm4W15IsdA6C4Ic5uvAfzMRPfqFoTCtoQzPPpNhykyZGdZYAYnuib2';
const failedWebhook = 'https://discord.com/api/webhooks/1532446989889966163/JLibn8NznDNNF3VmDz1EOBGi8tIOgKT9Eca2U56HeOpVgS3V8pEkUB9ETkIcNxeQb2O7';

// Minimum days since install (helps detect fresh pirated installs)
const MINIMUM_DAYS_SINCE_INSTALL = 0; // Set to 1+ to require aging period
const SUSPICIOUS_DAYS_THRESHOLD = 0; // Flag new installs as suspicious

// Expected device patterns for Quest devices
const EXPECTED_DEVICE_PATTERNS = ['Quest', 'Meta', 'Oculus'];

app.use(express.json());

/**
 * Decodes a base64url-encoded JSON string.
 */
function decodeBase64Url(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return JSON.parse(Buffer.from(input, 'base64').toString('utf8'));
}

/**
 * Perform basic security checks on client data
 */
function performSecurityChecks(payload) {
  const checks = [];
  const warnings = [];
  
  // 1. Check device model contains expected patterns
  const deviceModelValid = EXPECTED_DEVICE_PATTERNS.some(pattern => 
    payload.deviceModel?.toLowerCase().includes(pattern.toLowerCase())
  );
  checks.push({ name: 'Device Model Valid', passed: deviceModelValid });
  
  // 2. Check days since install
  const daysSinceInstallValid = payload.daysSinceInstall >= MINIMUM_DAYS_SINCE_INSTALL;
  checks.push({ name: 'Days Since Install Valid', passed: daysSinceInstallValid });
  
  if (payload.daysSinceInstall <= SUSPICIOUS_DAYS_THRESHOLD) {
    warnings.push(`Suspicious: New install (${payload.daysSinceInstall} days)`);
  }
  
  // 3. Check device type
  const deviceTypeValid = payload.deviceType === 'Handheld';
  checks.push({ name: 'Device Type Valid', passed: deviceTypeValid });
  
  // 4. Check Oculus ID format
  const oculusIdValid = payload.oculusId && payload.oculusId !== 'unknown' && payload.oculusId.length > 0;
  checks.push({ name: 'Oculus ID Valid', passed: oculusIdValid });
  
  // 5. Check Meta username
  const usernameValid = payload.metaUsername && payload.metaUsername !== 'unknown' && payload.metaUsername.length > 0;
  checks.push({ name: 'Meta Username Valid', passed: usernameValid });
  
  // 6. Check nonce exists and has proper length
  const nonceValid = payload.nonce && payload.nonce.length >= 20;
  checks.push({ name: 'Nonce Valid', passed: nonceValid });
  
  // 7. Check token exists
  const tokenValid = payload.token && payload.token.length > 0;
  checks.push({ name: 'Token Valid', passed: tokenValid });
  
  // 8. Check device unique ID exists
  const deviceIdValid = payload.deviceUniqueId && payload.deviceUniqueId.length > 0;
  checks.push({ name: 'Device Unique ID Valid', passed: deviceIdValid });
  
  // 9. Check payload completeness
  checks.push({ name: 'Payload Complete', passed: Object.keys(payload).length >= 8 });
  checks.push({ name: 'No Null Values in Critical Fields', passed: payload.oculusId && payload.metaUsername && payload.token });
  checks.push({ name: 'OS Version String Not Empty', passed: payload.osVersion && payload.osVersion.length > 0 });
  checks.push({ name: 'Device Model String Not Empty', passed: payload.deviceModel && payload.deviceModel.length > 0 });
  checks.push({ name: 'Days Since Install Non-Negative', passed: payload.daysSinceInstall >= 0 });
  
  const passedCount = checks.filter(c => c.passed).length;
  const totalCount = checks.length;
  
  return {
    checks,
    warnings,
    passedCount,
    totalCount,
    allPassed: passedCount === totalCount
  };
}

async function sendWebhook(webhook, title, description, color, fields = []) {
  try {
    await fetch(webhook, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        embeds: [
          {
            title: title,
            description: description,
            color: color,
            fields: fields,
            timestamp: new Date().toISOString(),
            footer: {
              text: 'ires tag attestation'
            }
          }
        ]
      })
    });
  } catch (error) {
    console.error('failed to send discord webhook:', error);
  }
}

app.post('/attestation', async (req, res) => {
  const payload = req.body;
  const { token, nonce, oculusId, metaUsername, osVersion, daysSinceInstall } = payload;
  
  console.log('Verifying with Meta:', { oculusId, metaUsername, osVersion, daysSinceInstall });

  if (!token || !nonce) {
    await sendWebhook(
      failedWebhook,
      '❌ attestation failed - missing data',
      'the attestation request was missing a token or nonce.',
      16711680,
      [
        { name: 'token', value: token ? 'provided' : 'missing', inline: true },
        { name: 'nonce', value: nonce ? 'provided' : 'missing', inline: true },
        { name: 'oculus id', value: oculusId || 'not provided', inline: true },
        { name: 'meta username', value: metaUsername || 'not provided', inline: true }
      ]
    );
    return res.status(400).json({ status: 'error', message: 'Missing token or nonce', errorCode: 400 });
  }

  // Perform security checks
  const securityCheckResult = performSecurityChecks(payload);
  console.log(`Security checks: ${securityCheckResult.passedCount}/${securityCheckResult.totalCount} passed`);
  
  if (!securityCheckResult.allPassed) {
    const failedChecks = securityCheckResult.checks
      .filter(c => !c.passed)
      .map(c => c.name)
      .join(', ');
    
    await sendWebhook(
      failedWebhook,
      '❌ attestation failed - security checks failed',
      `${securityCheckResult.passedCount}/${securityCheckResult.totalCount} security checks passed.`,
      16711680,
      [
        { name: 'oculus id', value: oculusId || 'unknown', inline: true },
        { name: 'meta username', value: metaUsername || 'unknown', inline: true },
        { name: 'days since install', value: daysSinceInstall?.toString() || 'unknown', inline: true },
        { name: 'checks passed', value: `${securityCheckResult.passedCount}/${securityCheckResult.totalCount}`, inline: true },
        { name: 'os version', value: osVersion || 'unknown', inline: false },
        { name: 'failed checks', value: failedChecks.substring(0, 1000) },
        { name: 'warnings', value: securityCheckResult.warnings.length > 0 ? securityCheckResult.warnings.join('\n') : 'none' }
      ]
    );
    
    return res.status(403).json({ 
      status: 'error', 
      message: `Security checks failed: ${failedChecks}`,
      errorCode: 403
    });
  }

  try {
    const url = `https://graph.oculus.com/platform_integrity/verify?token=${token}&access_token=${ACCESS_TOKEN}`;
    console.log(`Fetching attestation from Meta...`);
    const response = await fetch(url);
    const result = await response.json();

    let data = result.data;
    if (Array.isArray(data)) {
      data = data[0];
    }

    const message = data?.message;
    if (message !== 'success') {
      await sendWebhook(
        failedWebhook,
        '❌ attestation failed - meta rejection',
        'meta rejected the attestation token.',
        16711680,
        [
          { name: 'oculus id', value: oculusId || 'unknown', inline: true },
          { name: 'meta username', value: metaUsername || 'unknown', inline: true },
          { name: 'days since install', value: daysSinceInstall?.toString() || 'unknown', inline: true },
          { name: 'os version', value: osVersion || 'unknown', inline: false },
          { name: 'meta response', value: `\`\`\`json\n${JSON.stringify(result, null, 2).slice(0, 1000)}\n\`\`\`` }
        ]
      );
      return res.status(401).json({ status: 'invalid', message: 'Attestation failed', meta: result, errorCode: 401 });
    }

    let claimsPayload = null;
    if (typeof data.claims === 'string') {
      try {
        claimsPayload = decodeBase64Url(data.claims);
      } catch (e) {
        console.error('Failed to decode claims:', e);
        await sendWebhook(
          failedWebhook,
          '❌ attestation failed - malformed claims',
          'the claims data could not be decoded.',
          16711680,
          [
            { name: 'oculus id', value: oculusId || 'unknown', inline: true },
            { name: 'meta username', value: metaUsername || 'unknown', inline: true },
            { name: 'decode error', value: e.message || 'unknown error' }
          ]
        );
        return res.status(400).json({ status: 'error', message: 'Malformed claims data', meta: result, errorCode: 400 });
      }
    } else {
      await sendWebhook(
        failedWebhook,
        '❌ attestation failed - no claims',
        'no claims were found in the meta response.',
        16711680,
        [
          { name: 'oculus id', value: oculusId || 'unknown', inline: true },
          { name: 'meta username', value: metaUsername || 'unknown', inline: true },
          { name: 'meta response', value: `\`\`\`json\n${JSON.stringify(result, null, 2).slice(0, 1000)}\n\`\`\`` }
        ]
      );
      return res.status(400).json({ status: 'error', message: 'No claims found in Meta response', meta: result, errorCode: 400 });
    }

    const appState = claimsPayload.app_state;
    const deviceState = claimsPayload.device_state;
    const certMatch = appState?.package_cert_sha256_digest?.some((cert) => cert.toLowerCase() === expectedCertHash.toLowerCase());

    if (appState?.app_integrity_state !== 'StoreRecognized' || 
        appState?.package_id !== expectedPackageName || 
        !certMatch || 
        deviceState?.device_integrity_state !== 'Advanced') {
      
      let failedChecks = [];
      if (appState?.app_integrity_state !== 'StoreRecognized') {
        failedChecks.push(`app integrity state: ${appState?.app_integrity_state || 'missing'}`);
      }
      if (appState?.package_id !== expectedPackageName) {
        failedChecks.push(`package id: ${appState?.package_id || 'missing'}`);
      }
      if (!certMatch) {
        failedChecks.push('certificate hash did not match');
      }
      if (deviceState?.device_integrity_state !== 'Advanced') {
        failedChecks.push(`device integrity state: ${deviceState?.device_integrity_state || 'missing'}`);
      }

      await sendWebhook(
        failedWebhook,
        '❌ attestation failed - integrity checks',
        'the payload integrity checks failed.',
        16711680,
        [
          { name: 'oculus id', value: oculusId || 'unknown', inline: true },
          { name: 'meta username', value: metaUsername || 'unknown', inline: true },
          { name: 'days since install', value: daysSinceInstall?.toString() || 'unknown', inline: true },
          { name: 'os version', value: osVersion || 'unknown', inline: false },
          { name: 'failed checks', value: failedChecks.length > 0 ? failedChecks.join('\n') : 'unknown' },
          { name: 'app integrity state', value: appState?.app_integrity_state || 'missing', inline: true },
          { name: 'expected app state', value: 'StoreRecognized', inline: true },
          { name: 'package id', value: appState?.package_id || 'missing', inline: true },
          { name: 'expected package id', value: expectedPackageName, inline: true },
          { name: 'device integrity state', value: deviceState?.device_integrity_state || 'missing', inline: true },
          { name: 'expected device state', value: 'Advanced', inline: true }
        ]
      );

      return res.status(401).json({
        status: 'invalid',
        message: 'payload integrity checks failed',
        claims: claimsPayload,
        errorCode: 401
      });
    }

    // All checks passed!
    await sendWebhook(
      passedWebhook,
      '✅ attestation passed',
      `the attestation was verified and all ${securityCheckResult.totalCount} security checks passed.`,
      65280,
      [
        { name: 'oculus id', value: oculusId || 'unknown', inline: true },
        { name: 'meta username', value: metaUsername || 'unknown', inline: true },
        { name: 'days since install', value: daysSinceInstall?.toString() || 'unknown', inline: true },
        { name: 'os version', value: osVersion || 'unknown', inline: false },
        { name: 'device model', value: payload.deviceModel || 'unknown', inline: true },
        { name: 'security checks', value: `${securityCheckResult.passedCount}/${securityCheckResult.totalCount} ✅`, inline: true },
        { name: 'warnings', value: securityCheckResult.warnings.length > 0 ? securityCheckResult.warnings.join('\n') : 'none', inline: false },
        { name: 'app integrity state', value: appState?.app_integrity_state || 'missing', inline: true },
        { name: 'device integrity state', value: deviceState?.device_integrity_state || 'missing', inline: true },
        { name: 'certificate match', value: certMatch ? '✅ true' : '❌ false', inline: true }
      ]
    );

    return res.status(200).json({
      status: 'valid',
      message: 'Attestation verified and claims accepted',
      claims: claimsPayload,
      securityChecks: {
        passed: securityCheckResult.passedCount,
        total: securityCheckResult.totalCount
      }
    });
  } catch (error) {
    console.error('Error verifying token:', error);
    await sendWebhook(
      failedWebhook,
      '❌ attestation failed - server error',
      'the server encountered an error while verifying the attestation.',
      16711680,
      [
        { name: 'oculus id', value: oculusId || 'unknown', inline: true },
        { name: 'meta username', value: metaUsername || 'unknown', inline: true },
        { name: 'error', value: error.message || 'unknown error' }
      ]
    );
    return res.status(500).json({ status: 'error', message: 'Internal server error', error: error.message, errorCode: 500 });
  }
});

app.get('/', (req, res) => {
  res.send('<body style="background-color: black; color: red;">UNABLE TO AUTHENTICATE\nWITH BROTHERSHIP.</body>');
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
  console.log(`Security features enabled:`);
  console.log(`- Basic device integrity checks`);
  console.log(`- Days since install tracking (min: ${MINIMUM_DAYS_SINCE_INSTALL})`);
  console.log(`- Meta Platform attestation verification`);
});
