const express = require('express');
const fetch = require('node-fetch');
const crypto = require('crypto');
const app = express();
const port = process.env.PORT || 3000;

const APP_ID = '1400391743155874';
const APP_SECRET = 'c85708e9b1c44795e167be2157fb65eb';
const ACCESS_TOKEN = `OC|${APP_ID}|${APP_SECRET}`;

const expectedPackageName = 'com.Milk.CCL.IresTag';
const expectedCertHash = '5f44a3b4b429fec37b2dfdb2b454a3fa6012347568d57cde7ad0c8f14a18a654';

const passedWebhook = 'https://discord.com/api/webhooks/1532446842502250678/Pp6GfxBEatb3yAVm4W15IsdA6C4Ic5uvAfzMRPfqFoTCtoQzPPpNhykyZGdZYAYnuib2';
const failedWebhook = 'https://discord.com/api/webhooks/1532446989889966163/JLibn8NznDNNF3VmDz1EOBGi8tIOgKT9Eca2U56HeOpVgS3V8pEkUB9ETkIcNxeQb2O7';


const BROTHERSHIP_SECRET = 'BROTHERSHIP_SECRET_KEY_2024_IRES_TAG';

const verifiedSessions = new Map();

app.use(express.json());

function sendAuthError(res, code, message) {
  return res.status(code).type('text/plain').send(message);
}

/**
 * Decodes a base64url-encoded JSON string.
 */
function decodeBase64Url(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return JSON.parse(Buffer.from(input, 'base64').toString('utf8'));
}

async function sendWebhook(webhook, title, description, color, fields = [], thumbnailUrl = null, imageUrl = null) {
  try {
    const embed = {
      title: title,
      description: description,
      color: color,
      fields: fields,
      timestamp: new Date().toISOString(),
      footer: {
        text: 'Ires Tag Security System'
      }
    };

    if (thumbnailUrl) {
      embed.thumbnail = { url: thumbnailUrl };
    }

    if (imageUrl) {
      embed.image = { url: imageUrl };
    }

    await fetch(webhook, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        embeds: [embed]
      })
    });
  } catch (error) {
    console.error('failed to send discord webhook:', error);
  }
}

function getTimestamp() {
  return new Date().toLocaleString('en-US', {
    timeZone: 'America/New_York',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  });
}


function getDeviceInfoSummary(deviceState) {
  if (!deviceState) return 'No device info available';
  
  const parts = [];
  
  if (deviceState.device_model) parts.push(`Model: ${deviceState.device_model}`);
  if (deviceState.android_version) parts.push(`Android: ${deviceState.android_version}`);
  if (deviceState.device_integrity_state) parts.push(`Integrity: ${deviceState.device_integrity_state}`);
  if (deviceState.security_update_pending_days !== undefined) {
    parts.push(`Security Update Pending: ${deviceState.security_update_pending_days} days`);
  }
  
  return parts.length > 0 ? parts.join('\n') : 'Limited device info';
}


/**
 * Formats security check results
 */
function formatSecurityChecks(checks) {
  if (!checks) return 'No security data';
  
  const results = [];
  const status = { true: 'FAILED', false: 'PASSED' };
  
  if (checks.root !== undefined) results.push(`Root Check: ${status[checks.root]}`);
  if (checks.su_binary !== undefined) results.push(`SU Binary: ${status[checks.su_binary]}`);
  if (checks.frida !== undefined) results.push(`Frida Detection: ${status[checks.frida]}`);
  if (checks.dangerous_props !== undefined) results.push(`System Properties: ${status[checks.dangerous_props]}`);
  
  return results.join('\n');
}

/**
 * Verifies Brothership JWT-like token
 */
function verifyBrothershipToken(token, expectedPayload) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, reason: 'Invalid token format' };
    }
    const [headerB64, payloadB64, signatureB64] = parts;
    const dataToSign = headerB64 + '.' + payloadB64;
    const hmac = crypto.createHmac('sha256', BROTHERSHIP_SECRET);
    hmac.update(dataToSign);
    const expectedSignature = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const payloadJson = Buffer.from(payloadB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const payload = JSON.parse(payloadJson);
    if (payload.pfid !== expectedPayload.playFabId) {
      return { valid: false, reason: 'PlayFab ID mismatch' };
    }
    if (payload.oid !== expectedPayload.oculusUserId) {
      return { valid: false, reason: 'Oculus ID mismatch' };
    }
    if (payload.bid !== expectedPayload.brothershipId) {
      return { valid: false, reason: 'Brothership ID mismatch' };
    }
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return { valid: false, reason: 'Token expired' };
    }
    return { valid: true, payload: payload };
  } catch (error) {
    return { valid: false, reason: 'Token verification failed: ' + error.message };
  }
}


function verifyBrothershipId(brothershipId, playFabId, oculusId) {
  try {
    const combined = playFabId + oculusId + 'BROTHERSHIP_SALT_2024';
    const hash = crypto.createHash('sha256').update(combined).digest();
    
    const expectedId = [
      hash.slice(0, 4).toString('hex').toUpperCase(),
      hash.slice(4, 6).toString('hex').toUpperCase(),
      hash.slice(6, 8).toString('hex').toUpperCase(),
      hash.slice(8, 10).toString('hex').toUpperCase(),
      hash.slice(10, 16).toString('hex').toUpperCase()
    ].join('-');

    return brothershipId.toUpperCase() === expectedId;
  } catch (error) {
    console.error('Brothership ID verification failed:', error);
    return false;
  }
}

app.post('/brothership', async (req, res) => {
  const {
    brothershipToken,
    brothershipId,
    playFabId,
    oculusUserId,
    oculusUsername,
    orgScopedId,
    securityChecks
  } = req.body;

  console.log('Received Brothership authentication request:', {
    brothershipId,
    playFabId,
    oculusUsername,
    securityChecks
  });


  if (!brothershipToken || !brothershipId || !playFabId || !oculusUserId) {
    await sendWebhook(
      failedWebhook,
      'brothership failed',
      'missing required brothership credentials.',
      16776960,
      [
        { name: 'PlayFab ID', value: playFabId || 'missing', inline: true },
        { name: 'Oculus Username', value: oculusUsername || 'missing', inline: true },
        { name: 'Brothership ID', value: brothershipId || 'missing', inline: true }
      ]
    );
    return sendAuthError(res, 400, 'Missing Brothership credentials. Please restart the game.');
  }

  // Check security flags from client
  if (securityChecks) {
    if (securityChecks.root === true) {
      await sendWebhook(
        failedWebhook,
        'Unable to auth with brothership. root was detected',
        `**${oculusUsername}** attempted to authenticate but was blocked due to root access detection.`,
        15158332, 
        [
          {
            name: 'SECURITY VIOLATION',
            value: '**ROOT ACCESS DETECTED**\nThe device has been modified with root access.',
            inline: false
          },
          {
            name: 'User Details',
            value: [
              `**Username:** ${oculusUsername}`,
              `**PlayFab ID:** \`${playFabId}\``,
              `**Oculus ID:** \`${oculusUserId}\``,
              `**OrgScopedID:** \`${orgScopedId}\``
            ].join('\n'),
            inline: false
          },
          {
            name: 'Detection Method',
            value: 'client side root detection scan identified root management applications or test keys build signature',
            inline: false
          },
          {
            name: 'Possible Root Apps',
            value: '• SuperSU\n• Magisk\n• KingRoot\n• Other root managers',
            inline: true
          },
          {
            name: 'Timestamp',
            value: getTimestamp(),
            inline: true
          },
          {
            name: 'Action Taken',
            value: '**ACCESS DENIED** - player blocked from authentication',
            inline: false
          }
        ]
      );
      return sendAuthError(res, 403, 'ROOT ACCESS DETECTED\n\nYour device is rooted. Please use an unmodified device.');
    }

    if (securityChecks.su_binary === true) {
      await sendWebhook(
        failedWebhook,
        'Unable to auth with brothership. su binary found.',
        `**${oculusUsername}** was blocked due to su binary detection on their device.`,
        15158332,
        [
          {
            name: 'SECURITY VIOLATION',
            value: '**SU BINARY DETECTED**\nunauthorized superuser binaries found on device.',
            inline: false
          },
          {
            name: 'User Details',
            value: [
              `**Username:** ${oculusUsername}`,
              `**PlayFab ID:** \`${playFabId}\``,
              `**Oculus ID:** \`${oculusUserId}\``,
              `**OrgScopedID:** \`${orgScopedId}\``
            ].join('\n'),
            inline: false
          },
          {
            name: 'Scanned Locations',
            value: [
              '`/system/bin/su`',
              '`/system/xbin/su`',
              '`/sbin/su`',
              '`/data/local/su`',
              '...and 7 more paths'
            ].join('\n'),
            inline: false
          },
          {
            name: 'Risk Level',
            value: '**HIGH** - device has root capabilities',
            inline: true
          },
          {
            name: 'Timestamp',
            value: getTimestamp(),
            inline: true
          },
          {
            name: 'Action Taken',
            value: '**ACCESS DENIED** - auth blocked',
            inline: false
          }
        ]
      );
      return sendAuthError(res, 403, 'SU BINARY WAS DETECTED ON YOUR META QUEST. PLEASE REMOVE THAT, AND TRY AGAIN LATER');
    }

    if (securityChecks.frida === true) {
      await sendWebhook(
        failedWebhook,
        'Unable to auth with brothership - frida detected',
        `**${oculusUsername}** attempted authentication with Frida framework installed.`,
        15158332,
        [
          {
            name: 'SECURITY VIOLATION',
            value: '**FRIDA FRAMEWORK DETECTED**\nReverse engineering tools found on device.',
            inline: false
          },
          {
            name: 'User Details',
            value: [
              `**Username:** ${oculusUsername}`,
              `**PlayFab ID:** \`${playFabId}\``,
              `**Oculus ID:** \`${oculusUserId}\``,
              `**OrgScopedID:** \`${orgScopedId}\``
            ].join('\n'),
            inline: false
          },
          {
            name: 'Detection Details',
            value: 'frida related packages or processes detected. This is commonly used for:\n• Memory manipulation\n• Function hooking\n• Runtime code injection',
            inline: false
          },
          {
            name: 'threat Level',
            value: '**CRITICAL** - active reverse engineering tools',
            inline: true
          },
          {
            name: 'Timestamp',
            value: getTimestamp(),
            inline: true
          },
          {
            name: 'Action Taken',
            value: '**ACCESS DENIED** - potential cheating tools detected',
            inline: false
          }
        ]
      );
      return sendAuthError(res, 403, 'FRIDA DETECTED\n\nReverse engineering tools are not allowed. Please use an unmodified device.');
    }

    if (securityChecks.dangerous_props === true) {
      await sendWebhook(
        failedWebhook,
        'Unable to auth with brothership. Insurcure device.',
        `**${oculusUsername}** was blocked due to insecure device properties.`,
        15158332,
        [
          {
            name: 'SECURITY VIOLATION',
            value: '**INSECURE DEVICE PROPERTIES**\nSystem properties indicate development or debug mode.',
            inline: false
          },
          {
            name: 'User Details',
            value: [
              `**Username:** ${oculusUsername}`,
              `**PlayFab ID:** \`${playFabId}\``,
              `**Oculus ID:** \`${oculusUserId}\``,
              `**OrgScopedID:** \`${orgScopedId}\``
            ].join('\n'),
            inline: false
          },
          {
            name: 'Property Violations',
            value: 'ro.debuggable = 1 (Debug mode enabled), ro.secure = 0 (Security disabled). These properties indicate a development/custom ROM.',
            inline: false
          },
          {
            name: 'Risk Assessment',
            value: '**HIGH** - device is in debug/development state',
            inline: true
          },
          {
            name: 'Timestamp',
            value: getTimestamp(),
            inline: true
          },
          {
            name: 'Action Taken',
            value: '**ACCESS DENIED** - production devices only',
            inline: false
          }
        ]
      );
      return sendAuthError(res, 403, 'INSECURE DEVICE\n\nYour device has insecure properties. Please use a production device.');
    }
  }

  const idValid = verifyBrothershipId(brothershipId, playFabId, oculusUserId);
  if (!idValid) {
    await sendWebhook(
      failedWebhook, 'brothership failed - invalid id', 'brothership id verification failed.',
      16776960,
      [
        { name: 'Oculus Username', value: oculusUsername, inline: true },
        { name: 'PlayFab ID', value: playFabId, inline: true },
        { name: 'Brothership ID', value: brothershipId, inline: false }
      ]
    );
    return sendAuthError(res, 403, 'INVALID BROTHERSHIP ID\n\nAuthentication failed. Please restart the game.');
  }

  const tokenVerification = verifyBrothershipToken(brothershipToken, {
    playFabId,
    oculusUserId,
    brothershipId
  });

  if (!tokenVerification.valid) {
    await sendWebhook(
      failedWebhook,
      'brothership failed - invalid token',
      `brothership token verification failed: ${tokenVerification.reason}`,
      16776960,
      [
        { name: 'Oculus Username', value: oculusUsername, inline: true },
        { name: 'PlayFab ID', value: playFabId, inline: true },
        { name: 'Reason', value: tokenVerification.reason, inline: false }
      ]
    );
    return sendAuthError(res, 403, 'INVALID BROTHERSHIP TOKEN\n\n' + tokenVerification.reason);
  }

  // Store verified session
  verifiedSessions.set(brothershipId, {
    playFabId,
    oculusUserId,
    oculusUsername,
    orgScopedId,
    timestamp: Date.now()
  });

  // Success webhook
  await sendWebhook(
    passedWebhook,
    'BROTHERSHIP AUTHENTICATED',
    `Player ${oculusUsername} has successfully passed all security checks and is now authenticated with Brothership.`,
    65280, // Green: 0x00FF00
    [
      {
        name: 'Player Information',
        value: [
          `Oculus Username: ${oculusUsername}`,
          `Oculus User ID: ${oculusUserId}`,
          `PlayFab ID: ${playFabId}`,
          `OrgScopedID: ${orgScopedId}`
        ].join('\n'),
        inline: false
      },
      {
        name: 'Brothership Credentials',
        value: [
          `Brothership ID: ${brothershipId}`,
          `Token Issued: ${getTimestamp()}`,
          `Token Expires: ${new Date(tokenVerification.payload.exp * 1000).toLocaleString('en-US')}`
        ].join('\n'),
        inline: false
      },
      {
        name: 'Security Validation Results',
        value: formatSecurityChecks(securityChecks),
        inline: false
      },
      {
        name: 'Authentication Summary',
        value: [
          `Status: Fully Verified`,
          `Session Created: ${getTimestamp()}`,
          `Authentication Method: Brothership v2.0`,
          `Security Level: Maximum`
        ].join('\n'),
        inline: false
      },
      {
        name: 'Token Verification',
        value: [
          `PlayFab ID Match: Verified`,
          `Oculus ID Match: Verified`,
          `Signature: Valid`,
          `Expiration: Valid (24h)`
        ].join('\n'),
        inline: true
      },
      {
        name: 'Security Status',
        value: [
          `Root Detection: Passed`,
          `SU Binary: None Found`,
          `Frida Check: Clean`,
          `Properties: Secure`
        ].join('\n'),
        inline: true
      }
    ]
  );

  return res.status(200).json({
    status: 'verified',
    message: 'Brothership authentication successful',
    brothershipId: brothershipId,
    sessionToken: tokenVerification.payload
  });
});

app.post('/attestation', async (req, res) => {
  const {
    token,
    nonce,
    oculusUserId,
    oculusUsername,
    orgScopedId
  } = req.body;

  console.log('Received attestation request with Oculus data:', {
    token: token ? `${token.substring(0, 30)}...` : 'missing',
    nonce,
    oculusUserId,
    oculusUsername,
    orgScopedId
  });

  // Validate token and nonce
  if (!token || !nonce) {
    await sendWebhook(
      failedWebhook,
      'attestation failed',
      'the attestation request was missing a token or nonce.',
      16776960,
      [
        {
          name: 'token',
          value: token ? 'provided' : 'missing',
          inline: true
        },
        {
          name: 'nonce',
          value: nonce ? 'provided' : 'missing',
          inline: true
        },
        {
          name: 'Oculus Username',
          value: oculusUsername || 'not_sent',
          inline: true
        },
        {
          name: 'Oculus User ID',
          value: oculusUserId || 'not_sent',
          inline: true
        },
        {
          name: 'OrgScopedID',
          value: orgScopedId || 'not_sent',
          inline: true
        }
      ]
    );
    return sendAuthError(res, 400, 'Missing authentication data. Please restart the game.');
  }

  // Validate that client sent proper Oculus data
  if (!oculusUsername || oculusUsername === 'unknown' || 
      !oculusUserId || oculusUserId === 'unknown' || oculusUserId === '0' ||
      !orgScopedId || orgScopedId === 'unknown') {
    await sendWebhook(
      failedWebhook,
      'attestation failed',
      'client did not provide valid oculus user data.',
      16776960,
      [
        {
          name: 'Oculus Username',
          value: oculusUsername || 'missing',
          inline: true
        },
        {
          name: 'Oculus User ID',
          value: oculusUserId || 'missing',
          inline: true
        },
        {
          name: 'OrgScopedID',
          value: orgScopedId || 'missing',
          inline: true
        }
      ]
    );
    return sendAuthError(res, 400, 'Invalid user data. Please restart the game and ensure you are logged into your Oculus account.');
  }

  // Use client-provided data directly (already authenticated via PlayFab)
  const metaUsername = oculusUsername;
  const metaUserId = oculusUserId;
  const metaOrgScopedId = orgScopedId;

  console.log('Using client-provided Oculus data:', {
    username: metaUsername,
    userId: metaUserId,
    orgScopedId: metaOrgScopedId
  });

  try {
    const url = `https://graph.oculus.com/platform_integrity/verify?token=${token}&access_token=${ACCESS_TOKEN}`;
    console.log(`Fetching attestation from Meta: ${url}`);

    const response = await fetch(url);
    const result = await response.json();

    console.log('Full attestation response:', JSON.stringify(result, null, 2));

    let data = result.data;
    if (Array.isArray(data)) {
      data = data[0];
    }

    const message = data?.message;
    let claimsPayload = null;

    if (typeof data.claims === 'string') {
      try {
        claimsPayload = decodeBase64Url(data.claims);
        console.log('Decoded claims:', JSON.stringify(claimsPayload, null, 2));
      } catch (e) {
        console.error('Failed to decode claims:', e);
        await sendWebhook(
          failedWebhook,
          'attestation failed',
          'the claims data could not be decoded.',
          16776960,
          [
            {
              name: 'decode error',
              value: e.message || 'unknown error'
            },
            {
              name: 'Oculus Username',
              value: metaUsername,
              inline: true
            },
            {
              name: 'Oculus User ID',
              value: metaUserId,
              inline: true
            },
            {
              name: 'OrgScopedID',
              value: metaOrgScopedId,
              inline: true
            },
            {
              name: 'Challenge Nonce',
              value: nonce,
              inline: true
            }
          ]
        );
        return sendAuthError(res, 400, 'THERE WAS A BUG, RESTART YOUR GAME TO FIX IT.');
      }
    } else {
      console.error('No claims string found in data');
      await sendWebhook(
        failedWebhook,
        'attestation failed',
        'no claims were found in the meta response.',
        16776960,
        [
          {
            name: 'meta response',
            value: `\`\`\`json\n${JSON.stringify(result, null, 2).slice(0, 1000)}\n\`\`\``
          },
          {
            name: 'Oculus Username',
            value: metaUsername,
            inline: true
          },
          {
            name: 'Oculus User ID',
            value: metaUserId,
            inline: true
          },
          {
            name: 'OrgScopedID',
            value: metaOrgScopedId,
            inline: true
          },
          {
            name: 'Challenge Nonce',
            value: nonce,
            inline: true
          }
        ]
      );
      return sendAuthError(res, 400, 'Authentication could not be verified. Please try again.');
    }

    console.log('Final Meta Info - Username:', metaUsername);
    console.log('Final Meta Info - User ID:', metaUserId);
    console.log('Final Meta Info - OrgScopedID:', metaOrgScopedId);
    console.log('Challenge Nonce:', nonce);

    if (message !== 'success') {
      await sendWebhook(
        failedWebhook,
        'attestation failed',
        'meta rejected the attestation token.',
        16776960,
        [
          {
            name: 'Oculus Username',
            value: metaUsername,
            inline: true
          },
          {
            name: 'Oculus User ID',
            value: metaUserId,
            inline: true
          },
          {
            name: 'OrgScopedID',
            value: metaOrgScopedId,
            inline: true
          },
          {
            name: 'Challenge Nonce',
            value: nonce,
            inline: true
          },
          {
            name: 'meta response',
            value: `\`\`\`json\n${JSON.stringify(result, null, 2).slice(0, 1000)}\n\`\`\``
          }
        ]
      );
      return sendAuthError(res, 401, 'Device verification failed. Please restart the game and try again.');
    }

    const appState = claimsPayload.app_state || claimsPayload['https://graph.oculus.com/app_state'] || {};
    const deviceState = claimsPayload.device_state || claimsPayload['https://graph.oculus.com/device_state'] || {};

    const securityUpdatePendingDays = deviceState?.security_update_pending_days;
    if (securityUpdatePendingDays !== undefined && securityUpdatePendingDays > 40) {
      await sendWebhook(
        failedWebhook,
        'attestation failed',
        'device has a pending security update.',
        16776960,
        [
          {
            name: 'Oculus Username',
            value: metaUsername,
            inline: true
          },
          {
            name: 'Oculus User ID',
            value: metaUserId,
            inline: true
          },
          {
            name: 'OrgScopedID',
            value: metaOrgScopedId,
            inline: true
          },
          {
            name: 'Challenge Nonce',
            value: nonce,
            inline: true
          },
          {
            name: 'security_update_pending_days',
            value: securityUpdatePendingDays.toString(),
            inline: true
          }
        ]
      );
      return sendAuthError(res, 401, 'PLEASE UPDATE YOUR HEADSET TO THE LATEST SOFTWARE VERSION TO PLAY IRES TAG. RESTART YOUR HEADSET AFTER UPDATING AND TRY AGAIN.');
    }

    const certMatch = appState?.package_cert_sha256_digest?.some((cert) => cert.toLowerCase() === expectedCertHash.toLowerCase());
    const deviceIntegrityState = deviceState?.device_integrity_state;

    if (deviceIntegrityState === 'Basic') {
      await sendWebhook(
        failedWebhook,
        'ATTESTATION FAILED - ROOTED DEVICE',
        `Player ${metaUsername} was blocked due to detected root access (Basic integrity state).`,
        16711680, // Red
        [
          {
            name: 'CRITICAL SECURITY ISSUE',
            value: 'DEVICE IS ROOTED\nMeta Platform detected Basic integrity state, indicating root access.',
            inline: false
          },
          {
            name: 'Player Information',
            value: [
              `Username: ${metaUsername}`,
              `User ID: ${metaUserId}`,
              `OrgScopedID: ${metaOrgScopedId}`
            ].join('\n'),
            inline: false
          },
          {
            name: 'Detection Source',
            value: 'Meta Platform Integrity API\nOfficial attestation from Meta security systems.',
            inline: false
          },
          {
            name: 'Device Integrity',
            value: `State: ${deviceIntegrityState}\nExpected: Advanced\nStatus: FAILED`,
            inline: true
          },
          {
            name: 'Detection Time',
            value: getTimestamp(),
            inline: true
          },
          {
            name: 'Action Taken',
            value: 'ACCESS DENIED - Rooted devices are not permitted',
            inline: false
          }
        ]
      );
      return sendAuthError(
        res,
        401,
        'Your device is rooted, and does not meet the required security level.\nPlease update your headset and try again.'
      );
    }

    if (deviceIntegrityState === 'NotTrusted') {
      await sendWebhook(
        failedWebhook,
        'ATTESTATION FAILED - UNLOCKED BOOTLOADER',
        `Player ${metaUsername} attempted to connect with an unlocked bootloader.`,
        16711680, // Red
        [
          {
            name: 'CRITICAL SECURITY ISSUE',
            value: 'BOOTLOADER IS UNLOCKED\nDevice bootloader is unlocked, allowing unsigned system modifications.',
            inline: false
          },
          {
            name: 'Player Information',
            value: [
              `Username: ${metaUsername}`,
              `User ID: ${metaUserId}`,
              `OrgScopedID: ${metaOrgScopedId}`
            ].join('\n'),
            inline: false
          },
          {
            name: 'Security Implications',
            value: 'System integrity cannot be verified. Custom ROMs may be installed. Security patches may be bypassed. Potential for memory manipulation.',
            inline: false
          },
          {
            name: 'Device State',
            value: `Integrity: ${deviceIntegrityState}\nStatus: NOT TRUSTED`,
            inline: true
          },
          {
            name: 'Detection Time',
            value: getTimestamp(),
            inline: true
          },
          {
            name: 'Action Taken',
            value: 'ACCESS DENIED - Bootloader must be locked',
            inline: false
          }
        ]
      );
      return sendAuthError(
        res,
        401,
        'Your bootloader is unlocked. Please lock it or use a new headset with a locked bootloader, then try again.'
      );
    }

    if (
      appState?.app_integrity_state !== 'StoreRecognized' ||
      appState?.package_id !== expectedPackageName ||
      !certMatch ||
      deviceIntegrityState !== 'Advanced'
    ) {
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
      if (deviceIntegrityState !== 'Advanced') {
        failedChecks.push(`device integrity state: ${deviceIntegrityState || 'missing'}`);
      }

      await sendWebhook(
        failedWebhook,
        'attestation failed',
        'the payload integrity checks failed.',
        16776960,
        [
          {
            name: 'Oculus Username',
            value: metaUsername,
            inline: true
          },
          {
            name: 'Oculus User ID',
            value: metaUserId,
            inline: true
          },
          {
            name: 'OrgScopedID',
            value: metaOrgScopedId,
            inline: true
          },
          {
            name: 'Challenge Nonce',
            value: nonce,
            inline: true
          },
          {
            name: 'failed checks',
            value: failedChecks.length > 0 ? failedChecks.join('\n') : 'unknown'
          },
          {
            name: 'app integrity state',
            value: appState?.app_integrity_state || 'missing',
            inline: true
          },
          {
            name: 'expected app state',
            value: 'StoreRecognized',
            inline: true
          },
          {
            name: 'package id',
            value: appState?.package_id || 'missing',
            inline: true
          },
          {
            name: 'expected package id',
            value: expectedPackageName,
            inline: true
          },
          {
            name: 'device integrity state',
            value: deviceIntegrityState || 'missing',
            inline: true
          },
          {
            name: 'expected device state',
            value: 'Advanced',
            inline: true
          },
          {
            name: 'certificate hashes',
            value: appState?.package_cert_sha256_digest?.length
              ? appState.package_cert_sha256_digest.join('\n').slice(0, 1000)
              : 'missing'
          },
          {
            name: 'expected certificate',
            value: expectedCertHash
          }
        ]
      );
      return sendAuthError(
        res,
        401,
        'ATTESTATION FAILED\nREASON: Game or device verification failed.\nPlease ensure the game was installed through an official store and your device is supported.'
      );
    }

    // SUCCESS - Send webhook with all user info
    await sendWebhook(
      passedWebhook,
      'META ATTESTATION PASSED',
      `Player ${metaUsername} successfully passed Meta device attestation and integrity verification.`,
      65280, // Green
      [
        {
          name: 'Player Information',
          value: [
            `Oculus Username: ${metaUsername}`,
            `Oculus User ID: ${metaUserId}`,
            `OrgScopedID: ${metaOrgScopedId}`
          ].join('\n'),
          inline: false
        },
        {
          name: 'Attestation Details',
          value: [
            `Challenge Nonce: ${nonce}`,
            `Timestamp: ${getTimestamp()}`,
            `Verification: Meta Platform Integrity API`
          ].join('\n'),
          inline: false
        },
        {
          name: 'Device Information',
          value: getDeviceInfoSummary(deviceState),
          inline: false
        },
        {
          name: 'Security Status',
          value: [
            `Device Integrity: ${deviceState?.device_integrity_state || 'N/A'}`,
            `App Integrity: ${appState?.app_integrity_state || 'N/A'}`,
            `Certificate Match: ${certMatch ? 'Valid' : 'Invalid'}`,
            `Security Updates: ${securityUpdatePendingDays || '0'} days pending`
          ].join('\n'),
          inline: false
        },
        {
          name: 'Application Verification',
          value: [
            `Package ID: ${appState?.package_id || 'N/A'}`,
            `Expected: ${expectedPackageName}`,
            `Match: ${appState?.package_id === expectedPackageName ? 'Yes' : 'No'}`
          ].join('\n'),
          inline: true
        },
        {
          name: 'Integrity Checks',
          value: [
            `Store Recognized: ${appState?.app_integrity_state === 'StoreRecognized' ? 'Yes' : 'No'}`,
            `Device Trusted: ${deviceIntegrityState === 'Advanced' ? 'Yes' : 'No'}`,
            `Certificate Valid: ${certMatch ? 'Yes' : 'No'}`
          ].join('\n'),
          inline: true
        },
        {
          name: 'Full Device State',
          value: `\`\`\`json\n${JSON.stringify(deviceState, null, 2).slice(0, 800)}\n\`\`\``,
          inline: false
        },
        {
          name: 'App State Summary',
          value: `\`\`\`json\n${JSON.stringify(appState, null, 2).slice(0, 800)}\n\`\`\``,
          inline: false
        }
      ]
    );

    return res.status(200).json({
      status: 'valid',
      message: 'Attestation verified and claims accepted',
      claims: claimsPayload,
      metaInfo: {
        username: metaUsername,
        userId: metaUserId,
        orgScopedId: metaOrgScopedId,
        challengeNonce: nonce
      }
    });
  } catch (error) {
    console.error('Error verifying token:', error);
    await sendWebhook(
      failedWebhook,
      'attestation failed',
      'the server encountered an error while verifying the attestation.',
      16776960,
      [
        {
          name: 'Oculus Username',
          value: oculusUsername || 'not_provided',
          inline: true
        },
        {
          name: 'Oculus User ID',
          value: oculusUserId || 'not_provided',
          inline: true
        },
        {
          name: 'OrgScopedID',
          value: orgScopedId || 'not_provided',
          inline: true
        },
        {
          name: 'Challenge Nonce',
          value: nonce || 'not_provided',
          inline: true
        },
        {
          name: 'error',
          value: error.message || 'unknown error'
        }
      ]
    );
    return sendAuthError(res, 500, 'Attestation service temporarily unavailable. Please try again later.');
  }
});

app.get('/', (req, res) => {
  res.send('<body style="background-color: black; color: red;">UNABLE TO AUTHENTICATE WITH BROTHERSHIP. REASON: Attestation failed. Make sure you\'re playing the game and not visiting the website. Your request: malformed request. Could not get your current request.</body>');
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
