import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Email Security — real mail-flow/threat/campaign/policy dashboard backed by
// /api/email/* (api/email_security_enterprise.go). Was previously showing
// nothing at all: the shared ItdrScreen filtered /api/itdr/findings by
// type='email', a value that column never actually holds.
//
// widgets.dart already exports a top-level `sevColor(String)` — reused here
// rather than redeclared, unlike the (separately-authored) Cloud Security
// screen which shadows it locally.
// ─────────────────────────────────────────────────────────────────────────────

const _kRed    = Color(0xFFEF4444);
const _kOrange = Color(0xFFF97316);
const _kAmber  = Color(0xFFF59E0B);
const _kBlue   = Color(0xFF3B82F6);
const _kGreen  = Color(0xFF22C55E);
const _kPurple = Color(0xFF8B5CF6);
const _kGrey   = Color(0xFF6B7280);

Color _verdictColor(String v) => switch (v.toLowerCase()) {
  'malicious' => _kRed,
  'suspicious' => _kAmber,
  'clean' => _kGreen,
  _ => _kGrey,
};

class EmailSecurityScreen extends StatefulWidget {
  final DashboardApi api;
  const EmailSecurityScreen({super.key, required this.api});
  @override State<EmailSecurityScreen> createState() => _EmailSecurityState();
}

class _EmailSecurityState extends State<EmailSecurityScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 10, vsync: this);

  Map<String,dynamic>? _dashboard, _mailFlow, _authResults, _threatIntel, _analytics;
  List _messages = [], _threats = [], _attachments = [], _urls = [], _campaigns = [],
       _userRisk = [], _reported = [], _policies = [];
  bool _loading = true;

  final _msgSearchCtrl = TextEditingController();
  final _domainSearchCtrl = TextEditingController();
  Map<String,dynamic>? _senderIntelResult;
  bool _senderIntelLoading = false;

  @override
  void initState() { super.initState(); _load(); }

  @override
  void dispose() { _msgSearchCtrl.dispose(); _domainSearchCtrl.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await Future.wait([
      widget.api.emailDashboard(),
      widget.api.emailMailFlow(),
      widget.api.emailMessages(),
      widget.api.emailThreats(),
      widget.api.emailAttachments(),
      widget.api.emailUrls(),
      widget.api.emailAuthResults(),
      widget.api.emailCampaigns(),
      widget.api.emailThreatIntel(),
      widget.api.emailUserRisk(),
      widget.api.emailReported(),
      widget.api.emailPolicies(),
      widget.api.emailAnalytics(),
    ]);
    if (!mounted) return;
    setState(() {
      _dashboard    = r[0]  as Map<String,dynamic>?;
      _mailFlow     = r[1]  as Map<String,dynamic>?;
      _messages     = r[2]  as List;
      _threats      = r[3]  as List;
      _attachments  = r[4]  as List;
      _urls         = r[5]  as List;
      _authResults  = r[6]  as Map<String,dynamic>?;
      _campaigns    = r[7]  as List;
      _threatIntel  = r[8]  as Map<String,dynamic>?;
      _userRisk     = r[9]  as List;
      _reported     = r[10] as List;
      _policies     = r[11] as List;
      _analytics    = r[12] as Map<String,dynamic>?;
      _loading      = false;
    });
  }

  Future<void> _searchMessages() async {
    final q = _msgSearchCtrl.text.trim();
    final msgs = await widget.api.emailMessages(subject: q, sender: q);
    if (!mounted) return;
    setState(() => _messages = msgs);
  }

  Future<void> _respond(String action, Map<String,String> fields) async {
    final res = await widget.api.emailRespond({'action': action, ...fields});
    if (!mounted) return;
    final err = res?['error'];
    xSnack(context, err != null ? str(err) : str(res?['message'], 'Done'), error: err != null);
    _load();
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, isScrollable: true, tabs: const [
        Tab(text: 'Overview'), Tab(text: 'Messages'), Tab(text: 'Threats'),
        Tab(text: 'Attachments'), Tab(text: 'URLs'), Tab(text: 'Auth'),
        Tab(text: 'Campaigns'), Tab(text: 'Intelligence'), Tab(text: 'User Risk'),
        Tab(text: 'Policies'),
      ]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _overviewTab(), _messagesTab(), _threatsTab(), _attachmentsTab(), _urlsTab(),
        _authTab(), _campaignsTab(), _intelTab(), _userRiskTab(), _policiesTab(),
      ])),
    ]);
  }

  // ── Overview ────────────────────────────────────────────────────────────
  Widget _overviewTab() {
    final d = _dashboard ?? {};
    final flow = (_mailFlow?['steps'] as List?) ?? [];
    final a = _analytics ?? {};
    final topSenders = (a['top_senders'] as List?) ?? [];
    final topUrls = (a['top_blocked_urls'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Processed', value: str(d['emails_processed'], '0'), color: _kBlue, icon: Icons.mail_outline)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Blocked', value: str(d['emails_blocked'], '0'), color: _kRed, icon: Icons.block)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Phishing', value: str(d['phishing_attempts'], '0'), color: _kOrange, icon: Icons.phishing)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Malware', value: str(d['malware_attachments'], '0'), color: _kRed, icon: Icons.bug_report)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'BEC Attempts', value: str(d['bec_attempts'], '0'), color: _kPurple, icon: Icons.business_center)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Spam Rate', value: '${str(d['spam_rate'], '0')}%', color: _kAmber, icon: Icons.report)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'High-Risk Users', value: str(d['high_risk_users'], '0'), color: _kRed, icon: Icons.person_off)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Security Score', value: str(d['email_security_score'], '0'), color: _kGreen, icon: Icons.verified_user)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Mail Flow'),
      const SizedBox(height: 8),
      if (flow.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No mail flow data yet', style: TextStyle(color: Colors.grey)))
      else ...flow.map((s) {
        final m = s as Map<String,dynamic>;
        final dropped = (m['dropped'] as num?)?.toInt() ?? 0;
        final quarantined = (m['quarantined'] as num?)?.toInt() ?? 0;
        return _tile(
          icon: Icons.arrow_forward, iconColor: dropped > 0 ? _kRed : (quarantined > 0 ? _kAmber : _kGreen),
          title: str(m['label']),
          subtitle: dropped > 0 || quarantined > 0 ? '${dropped > 0 ? "$dropped dropped" : ""}${dropped > 0 && quarantined > 0 ? " · " : ""}${quarantined > 0 ? "$quarantined quarantined" : ""}' : null,
          trailing: '${str(m['count'])}',
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Top Senders'),
      const SizedBox(height: 8),
      if (topSenders.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No sender volume data yet', style: TextStyle(color: Colors.grey)))
      else ...topSenders.map((s) {
        final m = s as Map<String,dynamic>;
        return _tile(icon: Icons.person_outline, title: str(m['sender']), trailing: '${str(m['count'])} emails');
      }),
      const SizedBox(height: 16),
      SectionTitle('Top Blocked URL Domains'),
      const SizedBox(height: 8),
      if (topUrls.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No blocked URL domains yet', style: TextStyle(color: Colors.grey)))
      else ...topUrls.map((u) {
        final m = u as Map<String,dynamic>;
        return _tile(icon: Icons.link_off, iconColor: _kRed, title: str(m['domain']), trailing: '${str(m['count'])} hits');
      }),
    ]));
  }

  // ── Messages ────────────────────────────────────────────────────────────
  Widget _messagesTab() {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 6),
        child: Row(children: [
          Expanded(child: TextField(
            controller: _msgSearchCtrl,
            decoration: const InputDecoration(hintText: 'Search subject / sender…', isDense: true,
              prefixIcon: Icon(Icons.search, size: 18)),
            onSubmitted: (_) => _searchMessages(),
          )),
          const SizedBox(width: 8),
          FilledButton(onPressed: _searchMessages, child: const Text('Search')),
        ]),
      ),
      Expanded(child: _messages.isEmpty
        ? const XEmptyState('No messages found', icon: Icons.mail_outline)
        : RefreshIndicator(onRefresh: _load, child: ListView.builder(
            padding: const EdgeInsets.fromLTRB(12, 0, 12, 12), itemCount: _messages.length,
            itemBuilder: (_, i) {
              final m = _messages[i] as Map<String,dynamic>;
              final flagged = str(m['threat_type']).isNotEmpty && str(m['threat_type']) != 'clean';
              return Container(
                margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: flagged ? _kRed.withValues(alpha: .3) : Theme.of(context).colorScheme.outlineVariant),
                  color: flagged ? _kRed.withValues(alpha: .04) : null),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Expanded(child: Text(str(m['subject'], '(no subject)'),
                      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700),
                      maxLines: 1, overflow: TextOverflow.ellipsis)),
                    _Pill(label: str(m['status']).toUpperCase(), color: statusColor(str(m['status']))),
                  ]),
                  const SizedBox(height: 4),
                  Text('${str(m['sender'])} → ${str(m['recipient'])}',
                    style: const TextStyle(fontSize: 11, color: Colors.grey), maxLines: 1, overflow: TextOverflow.ellipsis),
                  const SizedBox(height: 4),
                  Row(children: [
                    if (m['has_attachment'] == true) const Padding(padding: EdgeInsets.only(right: 6),
                      child: Icon(Icons.attach_file, size: 13, color: Colors.grey)),
                    if ((m['url_count'] as num? ?? 0) > 0) Padding(padding: const EdgeInsets.only(right: 6),
                      child: Text('${m['url_count']} URLs', style: const TextStyle(fontSize: 10.5, color: Colors.grey))),
                    if (flagged) _Pill(label: str(m['threat_type']).toUpperCase(), color: _kRed),
                    const Spacer(),
                    Text(timeAgo(m['created_at']), style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
                  ]),
                ]),
              );
            },
          )),
      ),
    ]);
  }

  // ── Threats ─────────────────────────────────────────────────────────────
  Widget _threatsTab() {
    if (_threats.isEmpty) return const XEmptyState('No active email threats', icon: Icons.verified_user_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _threats.length,
      itemBuilder: (_, i) {
        final t = _threats[i] as Map<String,dynamic>;
        final score = (t['threat_score'] as num?)?.toInt() ?? 0;
        final sev = score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 30 ? 'medium' : 'low';
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(t['subject'], '(no subject)'),
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700), maxLines: 1, overflow: TextOverflow.ellipsis)),
              _Pill(label: str(t['threat_type']).toUpperCase(), color: sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text('${str(t['sender'])} → ${str(t['recipient'])} · score ${str(t['threat_score'],'0')}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 8),
            Wrap(spacing: 4, runSpacing: 4, children: [
              TextButton(onPressed: () => _respond('quarantine_email', {'message_id': str(t['message_id'])}),
                child: const Text('Quarantine', style: TextStyle(fontSize: 11))),
              TextButton(onPressed: () => _respond('delete_email', {'message_id': str(t['message_id'])}),
                child: const Text('Delete', style: TextStyle(fontSize: 11))),
              TextButton(onPressed: () => _respond('block_sender', {'sender': str(t['sender'])}),
                child: const Text('Block Sender', style: TextStyle(fontSize: 11))),
              TextButton(onPressed: () => _respond('create_incident', {'message_id': str(t['message_id']), 'sender': str(t['sender'])}),
                child: const Text('Escalate', style: TextStyle(fontSize: 11))),
            ]),
          ]),
        );
      },
    ));
  }

  // ── Attachments ─────────────────────────────────────────────────────────
  Widget _attachmentsTab() {
    if (_attachments.isEmpty) return const XEmptyState('No attachments scanned', icon: Icons.attach_file);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _attachments.length,
      itemBuilder: (_, i) {
        final a = _attachments[i] as Map<String,dynamic>;
        final verdict = str(a['verdict']);
        final malicious = verdict.toLowerCase() == 'malicious';
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: _verdictColor(verdict).withValues(alpha: .3)), color: _verdictColor(verdict).withValues(alpha: .04)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(a['filename']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700),
                maxLines: 1, overflow: TextOverflow.ellipsis)),
              _Pill(label: verdict.toUpperCase(), color: _verdictColor(verdict)),
            ]),
            const SizedBox(height: 4),
            Text('${str(a['file_type']).toUpperCase()} · ${str(a['file_size'],'0')} bytes',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 4),
            Row(children: [
              if (a['has_macros'] == true) const _Pill(label: 'MACROS', color: _kAmber),
              if (a['has_embedded'] == true) const Padding(padding: EdgeInsets.only(left: 4), child: _Pill(label: 'EMBEDDED', color: _kAmber)),
              if (a['has_signature'] == true) const Padding(padding: EdgeInsets.only(left: 4), child: _Pill(label: 'SIGNED', color: _kGreen)),
            ]),
            if (str(a['sandbox_result']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(str(a['sandbox_result']), style: const TextStyle(fontSize: 11), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
            if (malicious) ...[
              const SizedBox(height: 6),
              Align(alignment: Alignment.centerRight, child: TextButton(
                onPressed: () => _respond('block_hash', {'hash': str(a['sha256'])}),
                child: const Text('Block Hash', style: TextStyle(fontSize: 11)))),
            ],
          ]),
        );
      },
    ));
  }

  // ── URLs ─────────────────────────────────────────────────────────────────
  Widget _urlsTab() {
    if (_urls.isEmpty) return const XEmptyState('No URLs observed', icon: Icons.link);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _urls.length,
      itemBuilder: (_, i) {
        final u = _urls[i] as Map<String,dynamic>;
        final verdict = str(u['verdict']);
        final malicious = verdict.toLowerCase() == 'malicious';
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: _verdictColor(verdict).withValues(alpha: .3)), color: _verdictColor(verdict).withValues(alpha: .04)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(u['domain']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700),
                maxLines: 1, overflow: TextOverflow.ellipsis)),
              _Pill(label: verdict.toUpperCase(), color: _verdictColor(verdict)),
            ]),
            const SizedBox(height: 4),
            Text(str(u['url']), style: const TextStyle(fontSize: 11, color: Colors.grey), maxLines: 1, overflow: TextOverflow.ellipsis),
            const SizedBox(height: 4),
            Wrap(spacing: 4, runSpacing: 4, children: [
              if (u['is_shortened'] == true) const _Pill(label: 'SHORTENED', color: _kAmber),
              if (u['is_newly_registered'] == true) const _Pill(label: 'NEW DOMAIN', color: _kAmber),
              if (u['has_login_form'] == true) const _Pill(label: 'LOGIN FORM', color: _kOrange),
              if (u['is_typosquatting'] == true) const _Pill(label: 'TYPOSQUAT', color: _kRed),
              Text('${str(u['click_count'],'0')} clicks', style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
            ]),
            if (malicious) ...[
              const SizedBox(height: 6),
              Align(alignment: Alignment.centerRight, child: TextButton(
                onPressed: () => _respond('block_url', {'url': str(u['url']), 'domain': str(u['domain'])}),
                child: const Text('Block URL', style: TextStyle(fontSize: 11)))),
            ],
          ]),
        );
      },
    ));
  }

  // ── Auth Results ─────────────────────────────────────────────────────────
  Widget _authTab() {
    final summary = (_authResults?['summary'] as Map?) ?? {};
    final domains = (_authResults?['domains'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'SPF Pass', value: '${str(summary['spf_rate'],'0')}%', color: _kBlue, icon: Icons.verified)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'DKIM Pass', value: '${str(summary['dkim_rate'],'0')}%', color: _kPurple, icon: Icons.key)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'DMARC Pass', value: '${str(summary['dmarc_rate'],'0')}%', color: _kGreen, icon: Icons.shield)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Messages', value: str(summary['total'],'0'), color: _kGrey, icon: Icons.mail_outline)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('By Sending Domain'),
      const SizedBox(height: 8),
      if (domains.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No domain data yet', style: TextStyle(color: Colors.grey)))
      else ...domains.map((d) {
        final m = d as Map<String,dynamic>;
        final aligned = m['aligned'] == true;
        return Container(
          margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['domain']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: aligned ? 'ALIGNED' : 'NOT ALIGNED', color: aligned ? _kGreen : _kRed),
            ]),
            const SizedBox(height: 4),
            Row(children: [
              _Pill(label: 'SPF ${str(m['spf']).toUpperCase()}', color: str(m['spf']) == 'pass' ? _kGreen : _kRed),
              const SizedBox(width: 4),
              _Pill(label: 'DKIM ${str(m['dkim']).toUpperCase()}', color: str(m['dkim']) == 'pass' ? _kGreen : _kRed),
              const SizedBox(width: 4),
              _Pill(label: 'DMARC ${str(m['dmarc']).toUpperCase()}', color: str(m['dmarc']) == 'pass' ? _kGreen : _kRed),
            ]),
            const SizedBox(height: 4),
            Text('policy: ${str(m['policy'])} · ${str(m['count'],'0')} messages', style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
          ]),
        );
      }),
    ]));
  }

  // ── Campaigns ────────────────────────────────────────────────────────────
  Widget _campaignsTab() {
    if (_campaigns.isEmpty) return const XEmptyState('No phishing campaigns detected', icon: Icons.campaign_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _campaigns.length,
      itemBuilder: (_, i) {
        final c = _campaigns[i] as Map<String,dynamic>;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(c['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: str(c['status']).toUpperCase(), color: statusColor(str(c['status']))),
            ]),
            const SizedBox(height: 4),
            Text('${str(c['campaign_type']).replaceAll('_',' ')} · ${str(c['threat_actor'], 'unattributed')}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 4),
            Text('${str(c['email_count'],'0')} emails · ${str(c['victim_count'],'0')} victims · last seen ${timeAgo(c['last_seen'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(c['common_subject']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text('"${str(c['common_subject'])}"', style: const TextStyle(fontSize: 11.5, fontStyle: FontStyle.italic),
                maxLines: 1, overflow: TextOverflow.ellipsis),
            ],
          ]),
        );
      },
    ));
  }

  // ── Intelligence (threat-intel + sender lookup) ─────────────────────────
  Widget _intelTab() {
    final ti = _threatIntel ?? {};
    final maliciousDomains = (ti['malicious_domains'] as List?) ?? [];
    final threatActors = (ti['threat_actors'] as List?) ?? [];
    final byType = (ti['by_threat_type'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Sender / Domain Lookup'),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: TextField(
          controller: _domainSearchCtrl,
          decoration: const InputDecoration(hintText: 'domain or email…', isDense: true),
          onSubmitted: (_) => _lookupSender(),
        )),
        const SizedBox(width: 8),
        FilledButton(onPressed: _senderIntelLoading ? null : _lookupSender, child: const Text('Lookup')),
      ]),
      if (_senderIntelResult != null) ...[
        const SizedBox(height: 8),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(_senderIntelResult!['domain']), style: const TextStyle(fontWeight: FontWeight.w700))),
              _Pill(label: str(_senderIntelResult!['reputation']).toUpperCase(), color: _verdictColor(str(_senderIntelResult!['reputation']))),
            ]),
            const SizedBox(height: 4),
            Text('score ${str(_senderIntelResult!['reputation_score'],'0')} · '
              '${str(_senderIntelResult!['email_volume_7d'],'0')} emails (7d) · '
              '${str(_senderIntelResult!['threat_intel_hits'],'0')} IOC hits',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
          ]),
        ),
      ],
      const SizedBox(height: 16),
      SectionTitle('Malicious Domains'),
      const SizedBox(height: 8),
      if (maliciousDomains.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No malicious sending domains yet', style: TextStyle(color: Colors.grey)))
      else ...maliciousDomains.map((d) {
        final m = d as Map<String,dynamic>;
        return Container(
          margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Row(children: [
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(str(m['domain']), style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600)),
              Text('${str(m['category']).replaceAll('_',' ')} · ${str(m['hits'],'0')} hits since ${str(m['first_seen'])}',
                style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ])),
            TextButton(onPressed: () => _respond('block_domain', {'domain': str(m['domain'])}),
              child: const Text('Block', style: TextStyle(fontSize: 11))),
          ]),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Threat Actors'),
      const SizedBox(height: 8),
      if (threatActors.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No attributed campaigns yet', style: TextStyle(color: Colors.grey)))
      else ...threatActors.map((a) {
        final m = a as Map<String,dynamic>;
        return _tile(icon: Icons.groups_outlined, title: str(m['actor']),
          subtitle: '${str(m['campaigns'],'0')} campaigns', trailing: '${str(m['email_volume'],'0')} emails');
      }),
      const SizedBox(height: 16),
      SectionTitle('By Threat Type'),
      const SizedBox(height: 8),
      ...byType.map((t) {
        final m = t as Map<String,dynamic>;
        return _tile(icon: Icons.category_outlined, title: str(m['type']).replaceAll('_',' '), trailing: str(m['count']));
      }),
    ]));
  }

  Future<void> _lookupSender() async {
    final q = _domainSearchCtrl.text.trim();
    if (q.isEmpty) return;
    setState(() => _senderIntelLoading = true);
    final isEmail = q.contains('@');
    final res = await widget.api.emailSenderIntel(domain: isEmail ? '' : q, email: isEmail ? q : '');
    if (!mounted) return;
    setState(() { _senderIntelResult = res; _senderIntelLoading = false; });
  }

  // ── User Risk & Reported ─────────────────────────────────────────────────
  Widget _userRiskTab() {
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('High-Risk Users'),
      const SizedBox(height: 8),
      if (_userRisk.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No user risk data yet', style: TextStyle(color: Colors.grey)))
      else ..._userRisk.map((u) {
        final m = u as Map<String,dynamic>;
        final risk = (m['risk_score'] as num?)?.toInt() ?? 0;
        final sev = risk >= 70 ? 'critical' : risk >= 40 ? 'high' : 'low';
        return Container(
          margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Row(children: [
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(str(m['display_name'], str(m['email'])), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
              Text('${str(m['department'], 'unassigned')} · ${str(m['click_count'],'0')} clicks · ${str(m['phishing_failures'],'0')} failures',
                style: const TextStyle(fontSize: 11, color: Colors.grey)),
              Row(children: [
                if (m['is_repeated_victim'] == true) const _Pill(label: 'REPEAT VICTIM', color: _kRed),
                const SizedBox(width: 4),
                _Pill(label: str(m['training_status']).toUpperCase(), color: str(m['training_status']) == 'completed' ? _kGreen : _kAmber),
              ]),
            ])),
            Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
              _Pill(label: '$risk', color: sevColor(sev)),
              if (m['is_repeated_victim'] == true) TextButton(
                onPressed: () => _respond('reset_password', {'email': str(m['email'])}),
                child: const Text('Reset PW', style: TextStyle(fontSize: 10.5))),
            ]),
          ]),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('User-Reported Emails'),
      const SizedBox(height: 8),
      if (_reported.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No emails reported by users yet', style: TextStyle(color: Colors.grey)))
      else ..._reported.map((r) {
        final m = r as Map<String,dynamic>;
        final pending = str(m['triage_status']) == 'pending';
        return Container(
          margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['subject'], '(no subject)'), style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600),
                maxLines: 1, overflow: TextOverflow.ellipsis)),
              _Pill(label: str(m['triage_status']).toUpperCase(), color: pending ? _kAmber : _kGreen),
            ]),
            Text('reported by ${str(m['reporter_email'])} · from ${str(m['original_sender'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (pending) Align(alignment: Alignment.centerRight, child: TextButton(
              onPressed: () async {
                final ok = await widget.api.patchEmailReported((m['id'] as num?)?.toInt() ?? 0, triageStatus: 'reviewed');
                if (context.mounted) xSnack(context, ok ? 'Marked reviewed' : 'Failed', error: !ok);
                _load();
              },
              child: const Text('Mark Reviewed', style: TextStyle(fontSize: 11)))),
          ]),
        );
      }),
    ]));
  }

  // ── Policies ─────────────────────────────────────────────────────────────
  void _addPolicy() {
    final nameCtrl = TextEditingController();
    String type = 'attachment';
    String action = 'quarantine';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Email Policy'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xDropdown('Type', type, ['attachment','url','sender','content'], (v) => ss(() => type = v!)),
          const SizedBox(height: 10),
          xDropdown('Action', action, ['quarantine','block','allow','alert'], (v) => ss(() => action = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createEmailPolicy({
                'name': nameCtrl.text.trim(), 'policy_type': type, 'action': action,
              });
              if (context.mounted) xSnack(context, ok ? 'Policy created' : 'Failed', error: !ok);
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  Widget _policiesTab() {
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: SectionTitle('Policies')),
        TextButton(onPressed: _addPolicy, child: const Text('+ Add', style: TextStyle(fontSize: 12))),
      ]),
      const SizedBox(height: 8),
      if (_policies.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No email policies configured', style: TextStyle(color: Colors.grey)))
      else ..._policies.map((p) {
        final m = p as Map<String,dynamic>;
        final enabled = m['enabled'] == true;
        final id = (m['id'] as num?)?.toInt() ?? 0;
        return Container(
          margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Row(children: [
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(str(m['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
              Text('${str(m['policy_type'])} → ${str(m['action'])} · priority ${str(m['priority'],'0')}',
                style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ])),
            Switch(value: enabled, onChanged: (v) async {
              await widget.api.updateEmailPolicy(id, {'enabled': v});
              _load();
            }),
            IconButton(
              icon: const Icon(Icons.delete_outline, size: 18, color: _kRed),
              onPressed: () async {
                final ok = await widget.api.deleteEmailPolicy(id);
                if (context.mounted) xSnack(context, ok ? 'Policy deleted' : 'Failed', error: !ok);
                _load();
              },
            ),
          ]),
        );
      }),
    ]));
  }

  Widget _tile({required IconData icon, Color? iconColor, required String title, String? subtitle, String? trailing}) {
    return Container(
      margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
        color: Theme.of(context).colorScheme.surfaceContainerLow),
      child: Row(children: [
        Icon(icon, size: 16, color: iconColor ?? Colors.grey),
        const SizedBox(width: 10),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title, style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600),
            maxLines: 1, overflow: TextOverflow.ellipsis),
          if (subtitle != null && subtitle.isNotEmpty)
            Text(subtitle, style: const TextStyle(fontSize: 11, color: Colors.grey), maxLines: 1, overflow: TextOverflow.ellipsis),
        ])),
        if (trailing != null) Text(trailing, style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
      ]),
    );
  }
}

class _Pill extends StatelessWidget {
  final String label;
  final Color color;
  const _Pill({required this.label, required this.color});
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
    decoration: BoxDecoration(color: color.withValues(alpha: .12), borderRadius: BorderRadius.circular(5)),
    child: Text(label, style: TextStyle(fontSize: 9.5, fontWeight: FontWeight.w800, color: color)),
  );
}
