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

// Minimum allowed Meta OS version
const MINIMUM_HORIZON_OS_MAJOR = 2;
const MINIMUM_HORIZON_OS_MINOR = 5;
const MINIMUM_QUEST_BUILD = 85;

// Minimum days since install (helps detect fresh pirated installs)
const MINIMUM_DAYS_SINCE_INSTALL = 0; // Set to 1+ to require aging period
const SUSPICIOUS_DAYS_THRESHOLD = 0; // Flag new installs as suspicious

// Maximum failed attempts before permanent flag
const MAX_FAILED_ATTEMPTS = 3;

// Expected device characteristics for Quest devices
const EXPECTED_CPU_PATTERNS = ['Qualcomm', 'Snapdragon', 'ARM'];
const EXPECTED_GPU_PATTERNS = ['Adreno', 'Mali', 'Qualcomm'];
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
 * Parse OS version from the OS string
 */
function parseOSVersion(osString) {
  if (!osString) return null;
  
  const horizonMatch = osString.match(/Horizon\s+OS\s+(\d+)\.(\d+)|^(\d+)\.(\d+)/i);
  if (horizonMatch) {
    return {
      type: 'horizon',
      major: parseInt(horizonMatch[1] || horizonMatch[3]),
      minor: parseInt(horizonMatch[2] || horizonMatch[4]),
      build: null
    };
  }
  
  const questBuildMatch = osString.match(/(?:build|v)\s*(\d+)(?:\.(\d+))?/i);
  if (questBuildMatch) {
    return {
      type: 'quest_build',
      major: null,
      minor: null,
      build: parseInt(questBuildMatch[1])
    };
  }
  
  return null;
}

/**
 * Check if OS version meets minimum requirements
 */
function isOSVersionValid(version) {
  if (!version) return false;
  
  if (version.type === 'horizon') {
    if (version.major > MINIMUM_HORIZON_OS_MAJOR) {
      return true;
    }
    if (version.major === MINIMUM_HORIZON_OS_MAJOR) {
      return version.minor >= MINIMUM_HORIZON_OS_MINOR;
    }
    return false;
  }
  
  if (version.type === 'quest_build') {
    return version.build >= MINIMUM_QUEST_BUILD;
  }
  
  return false;
}

/**
 * Perform 30+ security checks on client data
 */
function performSecurityChecks(payload) {
  const checks = [];
  const warnings = [];
  
  // 1. Check OS version
  const parsedOS = parseOSVersion(payload.osVersion);
  checks.push({ name: 'OS Version Parsed', passed: parsedOS !== null });
  checks.push({ name: 'OS Version Valid', passed: isOSVersionValid(parsedOS) });
  
  // 2. Check device model contains expected patterns
  const deviceModelValid = EXPECTED_DEVICE_PATTERNS.some(pattern => 
    payload.deviceModel?.toLowerCase().includes(pattern.toLowerCase())
  );
  checks.push({ name: 'Device Model Valid', passed: deviceModelValid });
  
  // 3. Check CPU type
  const cpuValid = EXPECTED_CPU_PATTERNS.some(pattern => 
    payload.cpuType?.toLowerCase().includes(pattern.toLowerCase())
  );
  checks.push({ name: 'CPU Type Valid', passed: cpuValid });
  
  // 4. Check GPU
  const gpuValid = EXPECTED_GPU_PATTERNS.some(pattern => 
    payload.gpuName?.toLowerCase().includes(pattern.toLowerCase())
  );
  checks.push({ name: 'GPU Valid', passed: gpuValid });
  
  // 5. Check memory size (Quest 2: 6GB, Quest 3: 8GB+)
  const memoryValid = payload.memorySize >= 5000 && payload.memorySize <= 16000;
  checks.push({ name: 'Memory Size Valid', passed: memoryValid });
  
  // 6. Check days since install
  const daysSinceInstallValid = payload.daysSinceInstall >= MINIMUM_DAYS_SINCE_INSTALL;
  checks.push({ name: 'Days Since Install Valid', passed: daysSinceInstallValid });
  
  if (payload.daysSinceInstall <= SUSPICIOUS_DAYS_THRESHOLD) {
    warnings.push(`Suspicious: New install (${payload.daysSinceInstall} days)`);
  }
  
  // 7. Check failed attempt count
  const failedAttemptsValid = payload.failedAttemptCount < MAX_FAILED_ATTEMPTS;
  checks.push({ name: 'Failed Attempts Valid', passed: failedAttemptsValid });
  
  // 8. Check device type
  const deviceTypeValid = payload.deviceType === 'Handheld';
  checks.push({ name: 'Device Type Valid', passed: deviceTypeValid });
  
  // 9. Check for debug build (should be false in production)
  const notDebugBuild = payload.isDebugBuild === false;
  checks.push({ name: 'Not Debug Build', passed: notDebugBuild });
  if (payload.isDebugBuild) {
    warnings.push('Warning: Debug build detected');
  }
  
  // 10. Check Unity version format
  const unityVersionValid = /^\d+\.\d+\.\d+/.test(payload.unityVersion);
  checks.push({ name: 'Unity Version Format Valid', passed: unityVersionValid });
  
  // 11. Check build GUID exists
  const buildGuidValid = payload.buildGuid && payload.buildGuid.length > 0;
  checks.push({ name: 'Build GUID Valid', passed: buildGuidValid });
  
  // 12. Check graphics memory size (typical range for Quest)
  const graphicsMemoryValid = payload.graphicsMemorySize >= 512 && payload.graphicsMemorySize <= 4096;
  checks.push({ name: 'Graphics Memory Valid', passed: graphicsMemoryValid });
  
  // 13. Check processor count (Quest devices typically have 8 cores)
  const processorCountValid = payload.processorCount >= 4 && payload.processorCount <= 16;
  checks.push({ name: 'Processor Count Valid', passed: processorCountValid });
  
  // 14. Check processor frequency
  const processorFrequencyValid = payload.processorFrequency >= 1000 && payload.processorFrequency <= 5000;
  checks.push({ name: 'Processor Frequency Valid', passed: processorFrequencyValid });
  
  // 15. Check gyroscope support (required for VR)
  checks.push({ name: 'Gyroscope Supported', passed: payload.supportsGyroscope === true });
  
  // 16. Check accelerometer support (required for VR)
  checks.push({ name: 'Accelerometer Supported', passed: payload.supportsAccelerometer === true });
  
  // 17. Check Oculus ID format
  const oculusIdValid = payload.oculusId && payload.oculusId !== 'unknown' && payload.oculusId.length > 0;
  checks.push({ name: 'Oculus ID Valid', passed: oculusIdValid });
  
  // 18. Check Meta username
  const usernameValid = payload.metaUsername && payload.metaUsername !== 'unknown' && payload.metaUsername.length > 0;
  checks.push({ name: 'Meta Username Valid', passed: usernameValid });
  
  // 19. Check nonce exists and has proper length
  const nonceValid = payload.nonce && payload.nonce.length >= 20;
  checks.push({ name: 'Nonce Valid', passed: nonceValid });
  
  // 20. Check token exists
  const tokenValid = payload.token && payload.token.length > 0;
  checks.push({ name: 'Token Valid', passed: tokenValid });
  
  // 21. Check device unique ID exists
  const deviceIdValid = payload.deviceUniqueId && payload.deviceUniqueId.length > 0;
  checks.push({ name: 'Device Unique ID Valid', passed: deviceIdValid });
  
  // 22. Check graphics device version format
  const graphicsVersionValid = payload.graphicsDeviceVersion && payload.graphicsDeviceVersion.length > 0;
  checks.push({ name: 'Graphics Device Version Valid', passed: graphicsVersionValid });
  
  // 23-30. Additional integrity checks
  checks.push({ name: 'Payload Complete', passed: Object.keys(payload).length >= 15 });
  checks.push({ name: 'No Null Values in Critical Fields', passed: payload.oculusId && payload.metaUsername && payload.token });
  checks.push({ name: 'OS Version String Not Empty', passed: payload.osVersion && payload.osVersion.length > 0 });
  checks.push({ name: 'Device Model String Not Empty', passed: payload.deviceModel && payload.deviceModel.length > 0 });
  checks.push({ name: 'CPU Type String Not Empty', passed: payload.cpuType && payload.cpuType.length > 0 });
  checks.push({ name: 'GPU Name String Not Empty', passed: payload.gpuName && payload.gpuName.length > 0 });
  checks.push({ name: 'Memory Size Positive', passed: payload.memorySize > 0 });
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
              text: 'ires tag attestation v2.0'
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
  const { token, nonce, oculusId, metaUsername, osVersion, daysSinceInstall, failedAttemptCount } = payload;
  
  console.log('Verifying with Meta:', { oculusId, metaUsername, osVersion, daysSinceInstall, failedAttemptCount });

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

  // Perform 30+ security checks
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
        { name: 'failed attempts', value: failedAttemptCount?.toString() || '0', inline: true },
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
  res.send('<body style="background-color: black; color: red;">ofc your here... yes this game has attestation with 30+ security checks.</body>');
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
  console.log(`Security features enabled:`);
  console.log(`- 30+ device integrity checks`);
  console.log(`- Days since install tracking (min: ${MINIMUM_DAYS_SINCE_INSTALL})`);
  console.log(`- Failed attempts tracking (max: ${MAX_FAILED_ATTEMPTS})`);
  console.log(`- OS version validation (min Horizon OS ${MINIMUM_HORIZON_OS_MAJOR}.${MINIMUM_HORIZON_OS_MINOR} or Quest build ${MINIMUM_QUEST_BUILD})`);
});
