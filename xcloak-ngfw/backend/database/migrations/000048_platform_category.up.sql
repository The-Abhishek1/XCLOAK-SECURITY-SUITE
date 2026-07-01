-- Platform category taxonomy for agents and assets.
--
-- Allowed values (enforced by CHECK):
--   windows  — Windows desktop / server
--   linux    — Linux endpoints / servers (any distro)
--   macos    — macOS endpoints
--   ios      — Apple iOS / iPadOS mobile devices
--   android  — Android mobile devices
--   network  — routers, switches, firewalls, network appliances
--   web      — web application tier (manually tagged or asset_type='web_server')
--   cloud    — cloud workloads (EC2, Azure VM, GCP, containers)
--   iot      — IoT / embedded devices
--   other    — default / unrecognised

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS platform_category VARCHAR(30) NOT NULL DEFAULT 'other'
        CHECK (platform_category IN
            ('windows','linux','macos','ios','android','network','web','cloud','iot','other'));

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS platform_category VARCHAR(30) NOT NULL DEFAULT 'other'
        CHECK (platform_category IN
            ('windows','linux','macos','ios','android','network','web','cloud','iot','other'));

CREATE INDEX IF NOT EXISTS idx_agents_platform ON agents (tenant_id, platform_category);
CREATE INDEX IF NOT EXISTS idx_assets_platform ON assets (tenant_id, platform_category);

-- Back-fill agents that already have an os string.
-- This is a best-effort one-time update; the Go classifier keeps it current
-- going forward via agent registration and the 6h scheduler.
UPDATE agents SET platform_category =
    CASE
        WHEN LOWER(os) LIKE '%windows%'                          THEN 'windows'
        WHEN LOWER(os) LIKE '%ubuntu%'  OR LOWER(os) LIKE '%debian%'
          OR LOWER(os) LIKE '%centos%'  OR LOWER(os) LIKE '%rhel%'
          OR LOWER(os) LIKE '%fedora%'  OR LOWER(os) LIKE '%kali%'
          OR LOWER(os) LIKE '%amazon linux%' OR LOWER(os) LIKE '%suse%'
          OR LOWER(os) LIKE '%arch%'    OR LOWER(os) LIKE '%oracle linux%'
          OR LOWER(os) LIKE '%linux%'                            THEN 'linux'
        WHEN LOWER(os) LIKE '%darwin%'  OR LOWER(os) LIKE '%macos%'
          OR LOWER(os) LIKE '%mac os%'                           THEN 'macos'
        WHEN LOWER(os) LIKE '%android%'                          THEN 'android'
        WHEN LOWER(os) LIKE '%ios%' OR LOWER(os) LIKE '%iphone%'
          OR LOWER(os) LIKE '%ipad%'                             THEN 'ios'
        ELSE 'other'
    END
WHERE platform_category = 'other' AND os IS NOT NULL AND os <> '';

-- Back-fill assets: inherit from linked agent where possible, otherwise
-- derive from asset_type.
UPDATE assets a
SET platform_category = ag.platform_category
FROM agents ag
WHERE ag.id = a.agent_id
  AND ag.platform_category <> 'other'
  AND a.platform_category = 'other';

UPDATE assets SET platform_category =
    CASE
        WHEN asset_type IN ('web_server','web_application','web') THEN 'web'
        WHEN asset_type IN ('network_device','firewall','router','switch','network') THEN 'network'
        WHEN asset_type IN ('cloud_instance','cloud','container') THEN 'cloud'
        WHEN asset_type IN ('iot_device','iot') THEN 'iot'
        ELSE platform_category
    END
WHERE platform_category = 'other';
