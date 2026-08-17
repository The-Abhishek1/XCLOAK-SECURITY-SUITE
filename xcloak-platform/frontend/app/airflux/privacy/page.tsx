import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "AirFlux Privacy Policy",
  description: "Privacy policy for the AirFlux app by XCloak.",
};

export default function PrivacyPolicyPage() {
  return (
    <main className="min-h-screen bg-[#0A0E17] text-[#F5F7FA] px-6 py-16">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-3xl font-bold bg-gradient-to-r from-[#F5F7FA] to-[#00E5FF] bg-clip-text text-transparent">
          AirFlux Privacy Policy
        </h1>
        <p className="text-sm text-[#9AA5B8] mt-2 mb-10">
          Last updated: August 2026
        </p>

        <Section title="Overview">
          <p>
            AirFlux (&quot;the App&quot;) is developed by XCloak
            (&quot;we&quot;, &quot;us&quot;, &quot;our&quot;). This policy
            explains what information the App accesses, how it&apos;s used,
            and what it never does.
          </p>
        </Section>

        <Section title="Summary">
          <p>
            AirFlux is built to work without accounts, logins, or servers of
            ours in the middle. File transfers, downloads, and chat messages
            happen directly between your device and another device, or
            directly between your device and the website you&apos;re
            downloading from. We do not operate a backend server that
            stores, sees, or relays your files or messages.
          </p>
        </Section>

        <Section title="Information We Access On Your Device">
          <p className="mb-3">
            The App requests the following permissions, used only for the
            stated purpose:
          </p>
          <ul className="space-y-3 list-disc list-inside">
            <li>
              <strong className="text-[#F5F7FA]">Camera</strong> — used
              exclusively to scan QR codes for pairing with another device
              (file sharing and chat). The camera feed is never recorded,
              stored, or transmitted anywhere.
            </li>
            <li>
              <strong className="text-[#F5F7FA]">
                Storage / Media access
              </strong>{" "}
              — used to let you select files to share and to save files you
              download or receive. Files stay on your device.
            </li>
            <li>
              <strong className="text-[#F5F7FA]">Bluetooth</strong> — used
              only for Bluetooth Chat, to connect directly to another paired
              device. No data is sent to us or any third party.
            </li>
            <li>
              <strong className="text-[#F5F7FA]">Notifications</strong> —
              used to show download and transfer progress.
            </li>
            <li>
              <strong className="text-[#F5F7FA]">
                Local network / Wi-Fi state
              </strong>{" "}
              — used to run the local file-sharing server and Wi-Fi Chat,
              which operate entirely on your local network.
            </li>
          </ul>
        </Section>

        <Section title="Data Storage">
          <p>
            Transfer history, chat messages, and app settings are stored{" "}
            <strong className="text-[#F5F7FA]">
              locally on your device only
            </strong>
            , using a local database. Uninstalling the App removes this
            data. We do not have access to it and cannot recover it for
            you.
          </p>
        </Section>

        <Section title="Advertising">
          <p>
            The free version of AirFlux shows ads served through Google
            AdMob. AdMob may collect device identifiers and usage data to
            serve and measure ads, in accordance with{" "}
            
              href="https://policies.google.com/privacy"
              className="text-[#00E5FF] underline underline-offset-2"
              target="_blank"
              rel="noopener noreferrer"
            >
              Google&apos;s Privacy Policy
            </a>{" "}
            and{" "}
            
              href="https://support.google.com/admob/answer/6128543"
              className="text-[#00E5FF] underline underline-offset-2"
              target="_blank"
              rel="noopener noreferrer"
            >
              AdMob&apos;s data disclosure
            </a>
            . You can review Google&apos;s ad personalization settings in
            your device&apos;s Google Settings app. Purchasing AirFlux Pro
            removes ads.
          </p>
        </Section>

        <Section title="In-App Purchases">
          <p>
            AirFlux Pro is a one-time purchase processed entirely through
            Google Play Billing. We do not receive or store your payment
            information — that is handled by Google in accordance with{" "}
            
              href="https://play.google/developer-content-policy/"
              className="text-[#00E5FF] underline underline-offset-2"
              target="_blank"
              rel="noopener noreferrer"
            >
              Google Play&apos;s own policies
            </a>
            .
          </p>
        </Section>

        <Section title="What We Don't Do">
          <ul className="space-y-2 list-disc list-inside">
            <li>We do not require account creation or login.</li>
            <li>
              We do not operate a server that stores your files, messages,
              or transfer history.
            </li>
            <li>We do not sell your data to third parties.</li>
            <li>We do not track you across other apps or websites.</li>
          </ul>
        </Section>

        <Section title="Children's Privacy">
          <p>
            AirFlux is not directed at children under 13, and we do not
            knowingly collect data from children under 13.
          </p>
        </Section>

        <Section title="Changes to This Policy">
          <p>
            We may update this policy as the App evolves. Material changes
            will be reflected here with an updated &quot;Last updated&quot;
            date.
          </p>
        </Section>

        <Section title="Contact">
          <p>
            Questions about this policy can be sent to:{" "}
            
              href="mailto:your-email@xcloak.tech"
              className="text-[#00E5FF] underline underline-offset-2"
            >
              your-email@xcloak.tech
            </a>
          </p>
        </Section>

        <hr className="border-[#26344a] my-10" />
        <p className="text-sm text-[#5C6478]">
          AirFlux is developed by XCloak.
        </p>
      </div>
    </main>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-8">
      <h2 className="text-lg font-semibold text-[#00E5FF] border-b border-[#26344a] pb-2 mb-4">
        {title}
      </h2>
      <div className="text-[#C7CEDA] text-[15px] leading-relaxed">
        {children}
      </div>
    </section>
  );
}
