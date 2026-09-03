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

// Minimum allowed Meta OS version (block if below Horizon OS 2.5 or Quest build 85)
// Horizon OS uses format "2.x" while older Quest builds use numbers like "67", "72", "85"
const MINIMUM_HORIZON_OS_MAJOR = 2;
const MINIMUM_HORIZON_OS_MINOR = 5;
const MINIMUM_QUEST_BUILD = 85; // Last Quest build before Horizon OS 2.x

app.use(express.json());

/**
 * Decodes a base64url-encoded JSON string.
 * @param {string} input - Base64url-encoded string.
 * @returns {Object} - Decoded JSON object.
 */
function decodeBase64Url(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return JSON.parse(Buffer.from(input, 'base64').toString('utf8'));
}

/**
 * Parse OS version from the OS string
 * Expected formats:
 * - "Horizon OS 2.5" or "Meta Quest Horizon OS 2.5"
 * - "Quest v85" or "Meta Quest build 85.0"
 * - Full Android string: "Android OS 10 / API-29 (QQ3A.200805.001/eng.root.20200805.081611)"
 * @param {string} osString - The OS version string
 * @returns {Object|null} - Object with version info, or null if unable to parse
 */
function parseOSVersion(osString) {
  if (!osString) return null;
  
  // Try to match Horizon OS format: "Horizon OS 2.5" or "2.5"
  const horizonMatch = osString.match(/Horizon\s+OS\s+(\d+)\.(\d+)|^(\d+)\.(\d+)/i);
  if (horizonMatch) {
    return {
      type: 'horizon',
      major: parseInt(horizonMatch[1] || horizonMatch[3]),
      minor: parseInt(horizonMatch[2] || horizonMatch[4]),
      build: null
    };
  }
  
  // Try to match Quest build format: "v85", "build 85.0", "Quest build 85"
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
 * @param {Object} version - Object with version info from parseOSVersion
 * @returns {boolean} - True if version meets requirements
 */
function isOSVersionValid(version) {
  if (!version) return false;
  
  // For Horizon OS format (2.x)
  if (version.type === 'horizon') {
    if (version.major > MINIMUM_HORIZON_OS_MAJOR) {
      return true;
    }
    if (version.major === MINIMUM_HORIZON_OS_MAJOR) {
      return version.minor >= MINIMUM_HORIZON_OS_MINOR;
    }
    return false;
  }
  
  // For Quest build numbers (67, 72, 85, etc.)
  if (version.type === 'quest_build') {
    return version.build >= MINIMUM_QUEST_BUILD;
  }
  
  return false;
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
  const { token, nonce, oculusId, metaUsername, osVersion } = req.body;

  console.log('Verifying with Meta:', { token, nonce, oculusId, metaUsername, osVersion });

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
          name: 'oculus id',
          value: oculusId || 'not provided',
          inline: true
        },
        {
          name: 'meta username',
          value: metaUsername || 'not provided',
          inline: true
        }
      ]
    );
    return res.status(400).json({ status: 'error', message: 'Missing token or nonce' });
  }

  // Check OS version
  const parsedOSVersion = parseOSVersion(osVersion);
  console.log(`Parsed OS version:`, parsedOSVersion, `from "${osVersion}"`);
  
  if (parsedOSVersion !== null && !isOSVersionValid(parsedOSVersion)) {
    let versionString;
    let minVersionString;
    
    if (parsedOSVersion.type === 'horizon') {
      versionString = `Horizon OS ${parsedOSVersion.major}.${parsedOSVersion.minor}`;
      minVersionString = `Horizon OS ${MINIMUM_HORIZON_OS_MAJOR}.${MINIMUM_HORIZON_OS_MINOR}`;
    } else if (parsedOSVersion.type === 'quest_build') {
      versionString = `Quest build ${parsedOSVersion.build}`;
      minVersionString = `Quest build ${MINIMUM_QUEST_BUILD} or Horizon OS ${MINIMUM_HORIZON_OS_MAJOR}.${MINIMUM_HORIZON_OS_MINOR}`;
    } else {
      versionString = osVersion;
      minVersionString = `Horizon OS ${MINIMUM_HORIZON_OS_MAJOR}.${MINIMUM_HORIZON_OS_MINOR}`;
    }
    
    await sendWebhook(
      failedWebhook,
      'attestation failed - outdated os version',
      `User attempted to authenticate with an outdated Meta OS version.`,
      16776960,
      [
        {
          name: 'oculus id',
          value: oculusId || 'unknown',
          inline: true
        },
        {
          name: 'meta username',
          value: metaUsername || 'unknown',
          inline: true
        },
        {
          name: 'os version',
          value: osVersion || 'unknown',
          inline: true
        },
        {
          name: 'parsed version',
          value: versionString,
          inline: true
        },
        {
          name: 'minimum required',
          value: minVersionString,
          inline: true
        },
        {
          name: 'error',
          value: 'OS version too old. Please update your Meta Quest headset to the latest software version.'
        }
      ]
    );
    return res.status(404).json({ 
      status: 'error', 
      message: `OS version not supported. Please update your Meta Quest headset to Horizon OS ${MINIMUM_HORIZON_OS_MAJOR}.${MINIMUM_HORIZON_OS_MINOR} or higher (Quest build ${MINIMUM_QUEST_BUILD}+).`,
      errorCode: 404
    });
  }

  try {
    const url = `https://graph.oculus.com/platform_integrity/verify?token=${token}&access_token=${ACCESS_TOKEN}`;
    console.log(`Fetching attestation from Meta: ${url}`);

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
        'attestation failed',
        'meta rejected the attestation token.',
        16776960,
        [
          {
            name: 'oculus id',
            value: oculusId || 'unknown',
            inline: true
          },
          {
            name: 'meta username',
            value: metaUsername || 'unknown',
            inline: true
          },
          {
            name: 'os version',
            value: osVersion || 'unknown',
            inline: false
          },
          {
            name: 'meta response',
            value: `\`\`\`json\n${JSON.stringify(result, null, 2).slice(0, 1000)}\n\`\`\``
          }
        ]
      );
      return res.status(401).json({ status: 'invalid', message: 'Attestation failed', meta: result });
    }

    let claimsPayload = null;
    if (typeof data.claims === 'string') {
      try {
        claimsPayload = decodeBase64Url(data.claims);
      } catch (e) {
        console.error('Failed to decode claims:', e);
        await sendWebhook(
          failedWebhook,
          'attestation failed',
          'the claims data could not be decoded.',
          16776960,
          [
            {
              name: 'oculus id',
              value: oculusId || 'unknown',
              inline: true
            },
            {
              name: 'meta username',
              value: metaUsername || 'unknown',
              inline: true
            },
            {
              name: 'decode error',
              value: e.message || 'unknown error'
            }
          ]
        );
        return res.status(400).json({ status: 'error', message: 'Malformed claims data', meta: result });
      }
    } else {
      await sendWebhook(
        failedWebhook,
        'attestation failed',
        'no claims were found in the meta response.',
        16776960,
        [
          {
            name: 'oculus id',
            value: oculusId || 'unknown',
            inline: true
          },
          {
            name: 'meta username',
            value: metaUsername || 'unknown',
            inline: true
          },
          {
            name: 'meta response',
            value: `\`\`\`json\n${JSON.stringify(result, null, 2).slice(0, 1000)}\n\`\`\``
          }
        ]
      );
      return res.status(400).json({ status: 'error', message: 'No claims found in Meta response', meta: result });
    }

    const appState = claimsPayload.app_state;
    const deviceState = claimsPayload.device_state;

    const certMatch = appState?.package_cert_sha256_digest?.some((cert) => cert.toLowerCase() === expectedCertHash.toLowerCase());

    if (appState?.app_integrity_state !== 'StoreRecognized' || appState?.package_id !== expectedPackageName || !certMatch || deviceState?.device_integrity_state !== 'Advanced') {
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
        'attestation failed',
        'the payload integrity checks failed.',
        16776960,
        [
          {
            name: 'oculus id',
            value: oculusId || 'unknown',
            inline: true
          },
          {
            name: 'meta username',
            value: metaUsername || 'unknown',
            inline: true
          },
          {
            name: 'os version',
            value: osVersion || 'unknown',
            inline: false
          },
          {
            name: 'failed checks',
            value: failedChecks.length > 0
              ? failedChecks.join('\n')
              : 'unknown'
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
            value: deviceState?.device_integrity_state || 'missing',
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

      return res.status(401).json({
        status: 'invalid',
        message: 'payload integrity checks failed',
        claims: claimsPayload
      });
    }

    await sendWebhook(
      passedWebhook,
      'attestation passed ✅',
      'the attestation was verified and all claims were accepted.',
      65280,
      [
        {
          name: 'oculus id',
          value: oculusId || 'unknown',
          inline: true
        },
        {
          name: 'meta username',
          value: metaUsername || 'unknown',
          inline: true
        },
        {
          name: 'os version',
          value: osVersion || 'unknown',
          inline: false
        },
        {
          name: 'app integrity state',
          value: appState?.app_integrity_state || 'missing',
          inline: true
        },
        {
          name: 'package id',
          value: appState?.package_id || 'missing',
          inline: true
        },
        {
          name: 'device integrity state',
          value: deviceState?.device_integrity_state || 'missing',
          inline: true
        },
        {
          name: 'certificate match',
          value: certMatch ? 'true' : 'false',
          inline: true
        },
        {
          name: 'device state',
          value: `\`\`\`json\n${JSON.stringify(deviceState, null, 2).slice(0, 1000)}\n\`\`\``
        },
        {
          name: 'app state',
          value: `\`\`\`json\n${JSON.stringify(appState, null, 2).slice(0, 1000)}\n\`\`\``
        }
      ]
    );

    return res.status(200).json({
      status: 'valid',
      message: 'Attestation verified and claims accepted',
      claims: claimsPayload
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
          name: 'oculus id',
          value: oculusId || 'unknown',
          inline: true
        },
        {
          name: 'meta username',
          value: metaUsername || 'unknown',
          inline: true
        },
        {
          name: 'error',
          value: error.message || 'unknown error'
        }
      ]
    );
    return res.status(500).json({ status: 'error', message: 'Internal server error', error: error.message });
  }
});

app.get('/', (req, res) => {
  res.send('<body style="background-color: black; color: red;">ofc your here... yes this game has attestation.</body>');
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
