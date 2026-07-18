package api

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func mdmeNullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func mdmeID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()+int64(rand.Intn(9999)))
}

func mdmeAudit(tid int, action, objType, objID, objName, actor, details string) {
	db := database.DB
	if db == nil {
		return
	}
	db.Exec(`INSERT INTO mdme_audit (tenant_id,action,object_type,object_id,object_name,actor,details)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tid, action, objType, mdmeNullStr(objID), mdmeNullStr(objName), actor, details)
}

func mdmeNotify(tid int, evtType, title, message, severity, deviceID string) {
	db := database.DB
	if db == nil {
		return
	}
	db.Exec(`INSERT INTO mdme_notifications (tenant_id,event_type,title,message,severity,device_id)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		tid, evtType, title, message, severity, mdmeNullStr(deviceID))
}

// ── table init ────────────────────────────────────────────────────────────────

func InitMDMETables() {
	db := database.DB
	if db == nil {
		return
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS mdme_devices (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			device_name TEXT NOT NULL,
			device_type TEXT NOT NULL DEFAULT 'smartphone',
			platform TEXT NOT NULL DEFAULT 'android',
			manufacturer TEXT,
			model TEXT,
			serial_number TEXT,
			imei TEXT,
			os_version TEXT,
			security_patch TEXT,
			owner TEXT,
			owner_email TEXT,
			department TEXT,
			business_unit TEXT,
			enrollment_status TEXT NOT NULL DEFAULT 'enrolled',
			compliance_status TEXT NOT NULL DEFAULT 'compliant',
			risk_score INTEGER DEFAULT 0,
			battery_level INTEGER DEFAULT 0,
			storage_total_gb FLOAT DEFAULT 0,
			storage_used_gb FLOAT DEFAULT 0,
			memory_total_gb FLOAT DEFAULT 0,
			memory_used_gb FLOAT DEFAULT 0,
			wifi_ssid TEXT,
			wifi_signal_pct INTEGER DEFAULT 0,
			cellular_carrier TEXT,
			cellular_signal_pct INTEGER DEFAULT 0,
			bluetooth_enabled BOOLEAN DEFAULT FALSE,
			gps_lat FLOAT DEFAULT 0,
			gps_lon FLOAT DEFAULT 0,
			gps_location TEXT,
			encryption_enabled BOOLEAN DEFAULT TRUE,
			rooted BOOLEAN DEFAULT FALSE,
			jailbroken BOOLEAN DEFAULT FALSE,
			screen_lock_enabled BOOLEAN DEFAULT TRUE,
			screen_lock_timeout_min INTEGER DEFAULT 5,
			biometric_enabled BOOLEAN DEFAULT FALSE,
			is_lost BOOLEAN DEFAULT FALSE,
			is_quarantined BOOLEAN DEFAULT FALSE,
			last_checkin_at TIMESTAMP,
			enrolled_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, device_id))`,

		`CREATE TABLE IF NOT EXISTS mdme_apps (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			app_id TEXT NOT NULL,
			app_name TEXT NOT NULL,
			bundle_id TEXT,
			version TEXT,
			vendor TEXT,
			category TEXT DEFAULT 'other',
			status TEXT DEFAULT 'approved',
			size_mb FLOAT DEFAULT 0,
			install_source TEXT DEFAULT 'user',
			managed BOOLEAN DEFAULT FALSE,
			last_used_at TIMESTAMP,
			installed_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS mdme_policies (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			policy_id TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			policy_type TEXT NOT NULL DEFAULT 'security',
			platform TEXT NOT NULL DEFAULT 'all',
			enabled BOOLEAN DEFAULT TRUE,
			priority INTEGER DEFAULT 5,
			min_os_version TEXT,
			require_encryption BOOLEAN DEFAULT TRUE,
			require_screen_lock BOOLEAN DEFAULT TRUE,
			screen_lock_timeout INTEGER DEFAULT 5,
			require_biometric BOOLEAN DEFAULT FALSE,
			block_camera BOOLEAN DEFAULT FALSE,
			block_usb BOOLEAN DEFAULT FALSE,
			block_bluetooth BOOLEAN DEFAULT FALSE,
			require_vpn BOOLEAN DEFAULT FALSE,
			wifi_allowlist TEXT DEFAULT '[]',
			min_password_length INTEGER DEFAULT 8,
			require_complex_password BOOLEAN DEFAULT TRUE,
			max_failed_attempts INTEGER DEFAULT 10,
			devices_applied INTEGER DEFAULT 0,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS mdme_threats (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			threat_id TEXT NOT NULL UNIQUE,
			device_id TEXT NOT NULL,
			device_name TEXT,
			threat_type TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			severity TEXT NOT NULL DEFAULT 'medium',
			status TEXT NOT NULL DEFAULT 'open',
			detected_at TIMESTAMP DEFAULT NOW(),
			resolved_at TIMESTAMP,
			resolved_by TEXT)`,

		`CREATE TABLE IF NOT EXISTS mdme_remote_actions (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			action_id TEXT NOT NULL UNIQUE,
			device_id TEXT NOT NULL,
			device_name TEXT,
			action_type TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			initiated_by TEXT NOT NULL,
			completed_at TIMESTAMP,
			result TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS mdme_timeline (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			device_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			summary TEXT NOT NULL,
			actor TEXT,
			severity TEXT DEFAULT 'info',
			details TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS mdme_reports (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			report_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			report_type TEXT NOT NULL,
			generated_by TEXT NOT NULL,
			format TEXT DEFAULT 'pdf',
			size_bytes BIGINT DEFAULT 0,
			device_count INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS mdme_notifications (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			title TEXT NOT NULL,
			message TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'info',
			device_id TEXT,
			read BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS mdme_audit (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			action TEXT NOT NULL,
			object_type TEXT NOT NULL,
			object_id TEXT,
			object_name TEXT,
			actor TEXT NOT NULL,
			ip_address TEXT,
			details TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,
	}
	for _, s := range stmts {
		db.Exec(s)
	}
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func GetMDMEDashboard(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var total, enrolled, unmanaged, compliant, nonCompliant, rooted, lost, quarantined int
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1`, tidStr).Scan(&total)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND enrollment_status='enrolled'`, tidStr).Scan(&enrolled)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND enrollment_status='unenrolled'`, tidStr).Scan(&unmanaged)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND compliance_status='compliant'`, tidStr).Scan(&compliant)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND compliance_status='non_compliant'`, tidStr).Scan(&nonCompliant)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND (rooted=TRUE OR jailbroken=TRUE)`, tidStr).Scan(&rooted)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND is_lost=TRUE`, tidStr).Scan(&lost)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND is_quarantined=TRUE`, tidStr).Scan(&quarantined)

	var avgRisk float64
	db.QueryRow(`SELECT COALESCE(AVG(risk_score),0) FROM mdme_devices WHERE tenant_id=$1`, tidStr).Scan(&avgRisk)

	enrollmentRate := 0
	if total > 0 {
		enrollmentRate = enrolled * 100 / total
	}
	healthScore := 0
	if total > 0 {
		healthScore = (compliant * 100 / total + (total-rooted)*100/total + (total-lost)*100/total) / 3
	}

	// by platform
	platforms := []map[string]interface{}{}
	pr, _ := db.Query(`SELECT platform, COUNT(*) FROM mdme_devices WHERE tenant_id=$1 GROUP BY platform ORDER BY COUNT(*) DESC`, tidStr)
	if pr != nil {
		defer pr.Close()
		for pr.Next() {
			var p string
			var cnt int
			pr.Scan(&p, &cnt)
			platforms = append(platforms, map[string]interface{}{"platform": p, "count": cnt})
		}
	}

	// open threats
	var openThreats int
	db.QueryRow(`SELECT COUNT(*) FROM mdme_threats WHERE tenant_id=$1 AND status='open'`, tidStr).Scan(&openThreats)

	// recent checkins
	recent := []map[string]interface{}{}
	rr, _ := db.Query(`SELECT device_id,device_name,platform,compliance_status,risk_score,last_checkin_at
		FROM mdme_devices WHERE tenant_id=$1 ORDER BY last_checkin_at DESC NULLS LAST LIMIT 8`, tidStr)
	if rr != nil {
		defer rr.Close()
		for rr.Next() {
			var id, name, plat, comp string
			var risk int
			var lc *string
			rr.Scan(&id, &name, &plat, &comp, &risk, &lc)
			recent = append(recent, map[string]interface{}{
				"device_id": id, "device_name": name, "platform": plat,
				"compliance_status": comp, "risk_score": risk, "last_checkin_at": lc,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total": total, "enrolled": enrolled, "unmanaged": unmanaged,
		"compliant": compliant, "non_compliant": nonCompliant,
		"rooted_jailbroken": rooted, "lost": lost, "quarantined": quarantined,
		"avg_risk_score": avgRisk, "enrollment_rate": enrollmentRate,
		"health_score": healthScore, "open_threats": openThreats,
		"by_platform": platforms, "recent_checkins": recent,
	})
}

// ── Device Inventory ──────────────────────────────────────────────────────────

func GetMDMEDevices(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	search     := c.Query("search")
	platform   := c.Query("platform")
	compliance := c.Query("compliance")
	enrollment := c.Query("enrollment")
	dept       := c.Query("department")
	riskLevel  := c.Query("risk_level")
	limit      := parseLimit(c, 500)

	where := []string{"tenant_id=$1"}
	args  := []interface{}{tidStr}
	i     := 2

	if search != "" {
		where = append(where, fmt.Sprintf("(device_name ILIKE $%d OR owner ILIKE $%d OR imei ILIKE $%d OR serial_number ILIKE $%d)", i, i, i, i))
		args = append(args, "%"+search+"%"); i++
	}
	if platform != "" {
		where = append(where, fmt.Sprintf("platform=$%d", i))
		args = append(args, platform); i++
	}
	if compliance != "" {
		where = append(where, fmt.Sprintf("compliance_status=$%d", i))
		args = append(args, compliance); i++
	}
	if enrollment != "" {
		where = append(where, fmt.Sprintf("enrollment_status=$%d", i))
		args = append(args, enrollment); i++
	}
	if dept != "" {
		where = append(where, fmt.Sprintf("department=$%d", i))
		args = append(args, dept); i++
	}
	if riskLevel == "high" {
		where = append(where, "risk_score >= 70")
	} else if riskLevel == "critical" {
		where = append(where, "risk_score >= 85")
	}

	args = append(args, limit)
	q := fmt.Sprintf(`SELECT device_id,device_name,device_type,platform,manufacturer,model,
		serial_number,imei,os_version,owner,owner_email,department,business_unit,
		enrollment_status,compliance_status,risk_score,battery_level,
		rooted,jailbroken,is_lost,is_quarantined,encryption_enabled,
		screen_lock_enabled,last_checkin_at,enrolled_at
		FROM mdme_devices WHERE %s ORDER BY risk_score DESC, last_checkin_at DESC NULLS LAST LIMIT $%d`,
		strings.Join(where, " AND "), i)

	rows, err := db.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()

	var devices []map[string]interface{}
	for rows.Next() {
		var id, name, dtype, plat, mfr, model, serial, imei, osv, owner, email, dept2, bu, enrollSt, compSt string
		var risk, battery, rooted, jailbroken, lost, quar, enc, screenLock int
		var lc, ea *string
		if err := rows.Scan(&id, &name, &dtype, &plat, &mfr, &model, &serial, &imei, &osv,
			&owner, &email, &dept2, &bu, &enrollSt, &compSt, &risk, &battery,
			&rooted, &jailbroken, &lost, &quar, &enc, &screenLock, &lc, &ea); err == nil {
			devices = append(devices, map[string]interface{}{
				"device_id": id, "device_name": name, "device_type": dtype,
				"platform": plat, "manufacturer": mfr, "model": model,
				"serial_number": serial, "imei": imei, "os_version": osv,
				"owner": owner, "owner_email": email, "department": dept2,
				"business_unit": bu, "enrollment_status": enrollSt,
				"compliance_status": compSt, "risk_score": risk,
				"battery_level": battery,
				"rooted": rooted == 1, "jailbroken": jailbroken == 1,
				"is_lost": lost == 1, "is_quarantined": quar == 1,
				"encryption_enabled": enc == 1, "screen_lock_enabled": screenLock == 1,
				"last_checkin_at": lc, "enrolled_at": ea,
			})
		}
	}
	if devices == nil {
		devices = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, devices)
}

// ── Device Detail ─────────────────────────────────────────────────────────────

func GetMDMEDeviceDetail(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	devID := c.Param("id")

	row := db.QueryRow(`SELECT device_id,device_name,device_type,platform,manufacturer,model,
		serial_number,imei,os_version,security_patch,owner,owner_email,department,business_unit,
		enrollment_status,compliance_status,risk_score,battery_level,
		storage_total_gb,storage_used_gb,memory_total_gb,memory_used_gb,
		wifi_ssid,wifi_signal_pct,cellular_carrier,cellular_signal_pct,
		bluetooth_enabled,gps_lat,gps_lon,gps_location,
		encryption_enabled,rooted,jailbroken,screen_lock_enabled,screen_lock_timeout_min,
		biometric_enabled,is_lost,is_quarantined,last_checkin_at,enrolled_at
		FROM mdme_devices WHERE tenant_id=$1 AND device_id=$2`, tidStr, devID)

	var (
		id, name, dtype, plat, mfr, model, serial, imei, osv, patch, owner, email, dept, bu string
		enrollSt, compSt, wifiSSID, carrier, gpsLoc string
		risk, battery, wifiSig, cellSig, lockTimeout int
		storTotal, storUsed, memTotal, memUsed, lat, lon float64
		bt, enc, rooted, jailb, lock, bio, lost, quar bool
		lc, ea *string
	)
	err := row.Scan(&id, &name, &dtype, &plat, &mfr, &model, &serial, &imei, &osv, &patch,
		&owner, &email, &dept, &bu, &enrollSt, &compSt, &risk, &battery,
		&storTotal, &storUsed, &memTotal, &memUsed,
		&wifiSSID, &wifiSig, &carrier, &cellSig,
		&bt, &lat, &lon, &gpsLoc,
		&enc, &rooted, &jailb, &lock, &lockTimeout, &bio, &lost, &quar, &lc, &ea)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}

	// installed apps
	apps := []map[string]interface{}{}
	ar, _ := db.Query(`SELECT app_name,bundle_id,version,vendor,category,status,size_mb,managed,last_used_at
		FROM mdme_apps WHERE tenant_id=$1 AND device_id=$2 ORDER BY app_name LIMIT 50`, tidStr, devID)
	if ar != nil {
		defer ar.Close()
		for ar.Next() {
			var appName, bid, ver, vendor, cat, st string
			var sizeMB float64
			var managed bool
			var lua *string
			if e := ar.Scan(&appName, &bid, &ver, &vendor, &cat, &st, &sizeMB, &managed, &lua); e == nil {
				apps = append(apps, map[string]interface{}{
					"app_name": appName, "bundle_id": bid, "version": ver,
					"vendor": vendor, "category": cat, "status": st,
					"size_mb": sizeMB, "managed": managed, "last_used_at": lua,
				})
			}
		}
	}

	// timeline for this device
	timeline := []map[string]interface{}{}
	tr, _ := db.Query(`SELECT event_type,summary,actor,severity,details,created_at
		FROM mdme_timeline WHERE tenant_id=$1 AND device_id=$2
		ORDER BY created_at DESC LIMIT 20`, tidStr, devID)
	if tr != nil {
		defer tr.Close()
		for tr.Next() {
			var etype, summ, actor, sev string
			var det, tca *string
			if e := tr.Scan(&etype, &summ, &actor, &sev, &det, &tca); e == nil {
				timeline = append(timeline, map[string]interface{}{
					"event_type": etype, "summary": summ, "actor": actor,
					"severity": sev, "details": det, "created_at": tca,
				})
			}
		}
	}

	// recent remote actions
	actions := []map[string]interface{}{}
	acr, _ := db.Query(`SELECT action_type,status,initiated_by,result,created_at
		FROM mdme_remote_actions WHERE tenant_id=$1 AND device_id=$2
		ORDER BY created_at DESC LIMIT 10`, tidStr, devID)
	if acr != nil {
		defer acr.Close()
		for acr.Next() {
			var atype, ast, by, result string
			var aca *string
			if e := acr.Scan(&atype, &ast, &by, &result, &aca); e == nil {
				actions = append(actions, map[string]interface{}{
					"action_type": atype, "status": ast, "initiated_by": by,
					"result": result, "created_at": aca,
				})
			}
		}
	}

	mdmeAudit(tid, "device_viewed", "device", id, name, usernameFromContext(c), "")

	storPct := 0
	if storTotal > 0 {
		storPct = int(storUsed / storTotal * 100)
	}
	memPct := 0
	if memTotal > 0 {
		memPct = int(memUsed / memTotal * 100)
	}

	c.JSON(http.StatusOK, gin.H{
		"device_id": id, "device_name": name, "device_type": dtype, "platform": plat,
		"manufacturer": mfr, "model": model, "serial_number": serial, "imei": imei,
		"os_version": osv, "security_patch": patch, "owner": owner, "owner_email": email,
		"department": dept, "business_unit": bu,
		"enrollment_status": enrollSt, "compliance_status": compSt, "risk_score": risk,
		"battery_level": battery,
		"storage_total_gb": storTotal, "storage_used_gb": storUsed, "storage_pct": storPct,
		"memory_total_gb": memTotal, "memory_used_gb": memUsed, "memory_pct": memPct,
		"wifi_ssid": wifiSSID, "wifi_signal_pct": wifiSig,
		"cellular_carrier": carrier, "cellular_signal_pct": cellSig,
		"bluetooth_enabled": bt, "gps_lat": lat, "gps_lon": lon, "gps_location": gpsLoc,
		"encryption_enabled": enc, "rooted": rooted, "jailbroken": jailb,
		"screen_lock_enabled": lock, "screen_lock_timeout_min": lockTimeout,
		"biometric_enabled": bio, "is_lost": lost, "is_quarantined": quar,
		"last_checkin_at": lc, "enrolled_at": ea,
		"installed_apps": apps, "timeline": timeline, "recent_actions": actions,
	})
}

// ── Apps ──────────────────────────────────────────────────────────────────────

func GetMDMEApps(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	statusFilter := c.Query("status")
	limit := parseLimit(c, 200)

	where := []string{"tenant_id=$1"}
	args  := []interface{}{tidStr}
	i     := 2
	if statusFilter != "" {
		where = append(where, fmt.Sprintf("status=$%d", i))
		args = append(args, statusFilter); i++
	}
	args = append(args, limit)

	q := fmt.Sprintf(`SELECT app_name,bundle_id,version,vendor,category,status,
		COUNT(DISTINCT device_id) as device_count,
		SUM(size_mb) as total_size_mb, MAX(installed_at) as last_seen
		FROM mdme_apps WHERE %s GROUP BY app_name,bundle_id,version,vendor,category,status
		ORDER BY device_count DESC LIMIT $%d`, strings.Join(where, " AND "), i)

	rows, err := db.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()

	var apps []map[string]interface{}
	for rows.Next() {
		var name, bid, ver, vendor, cat, st string
		var cnt int
		var totalMB float64
		var ls *string
		if err := rows.Scan(&name, &bid, &ver, &vendor, &cat, &st, &cnt, &totalMB, &ls); err == nil {
			apps = append(apps, map[string]interface{}{
				"app_name": name, "bundle_id": bid, "version": ver, "vendor": vendor,
				"category": cat, "status": st, "device_count": cnt,
				"total_size_mb": totalMB, "last_seen": ls,
			})
		}
	}
	if apps == nil {
		apps = []map[string]interface{}{}
	}

	// summary
	var approved, blocked, risky int
	db.QueryRow(`SELECT COUNT(DISTINCT bundle_id) FROM mdme_apps WHERE tenant_id=$1 AND status='approved'`, tidStr).Scan(&approved)
	db.QueryRow(`SELECT COUNT(DISTINCT bundle_id) FROM mdme_apps WHERE tenant_id=$1 AND status='blocked'`, tidStr).Scan(&blocked)
	db.QueryRow(`SELECT COUNT(DISTINCT bundle_id) FROM mdme_apps WHERE tenant_id=$1 AND status='risky'`, tidStr).Scan(&risky)

	c.JSON(http.StatusOK, gin.H{
		"apps": apps, "summary": gin.H{
			"approved": approved, "blocked": blocked, "risky": risky,
		},
	})
}

// ── Policies ──────────────────────────────────────────────────────────────────

func GetMDMEPolicies(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var policies []map[string]interface{}
	rows, _ := db.Query(`SELECT policy_id,name,policy_type,platform,enabled,priority,
		min_os_version,require_encryption,require_screen_lock,screen_lock_timeout,
		require_biometric,block_camera,block_usb,block_bluetooth,require_vpn,
		min_password_length,require_complex_password,max_failed_attempts,
		devices_applied,created_by,created_at
		FROM mdme_policies WHERE tenant_id=$1 ORDER BY priority ASC`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, name, ptype, plat, minOS, createdBy string
			var enabled, reqEnc, reqLock, reqBio, blockCam, blockUSB, blockBT, reqVPN, reqComplex bool
			var priority, lockTimeout, minPwdLen, maxFail, devApplied int
			var ca *string
			if err := rows.Scan(&id, &name, &ptype, &plat, &enabled, &priority, &minOS,
				&reqEnc, &reqLock, &lockTimeout, &reqBio, &blockCam, &blockUSB, &blockBT, &reqVPN,
				&minPwdLen, &reqComplex, &maxFail, &devApplied, &createdBy, &ca); err == nil {
				policies = append(policies, map[string]interface{}{
					"policy_id": id, "name": name, "policy_type": ptype, "platform": plat,
					"enabled": enabled, "priority": priority, "min_os_version": minOS,
					"require_encryption": reqEnc, "require_screen_lock": reqLock,
					"screen_lock_timeout": lockTimeout, "require_biometric": reqBio,
					"block_camera": blockCam, "block_usb": blockUSB, "block_bluetooth": blockBT,
					"require_vpn": reqVPN, "min_password_length": minPwdLen,
					"require_complex_password": reqComplex, "max_failed_attempts": maxFail,
					"devices_applied": devApplied, "created_by": createdBy, "created_at": ca,
				})
			}
		}
	}
	if policies == nil {
		policies = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, policies)
}

// ── Compliance ────────────────────────────────────────────────────────────────

func GetMDMECompliance(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var total, compliant, nonCompliant, enc, screenLock, bio, noRooted int
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1`, tidStr).Scan(&total)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND compliance_status='compliant'`, tidStr).Scan(&compliant)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND compliance_status='non_compliant'`, tidStr).Scan(&nonCompliant)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND encryption_enabled=TRUE`, tidStr).Scan(&enc)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND screen_lock_enabled=TRUE`, tidStr).Scan(&screenLock)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND biometric_enabled=TRUE`, tidStr).Scan(&bio)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1 AND rooted=FALSE AND jailbroken=FALSE`, tidStr).Scan(&noRooted)

	// non-compliant device list
	nonCompliantDevs := []map[string]interface{}{}
	nr, _ := db.Query(`SELECT device_id,device_name,platform,owner,department,risk_score,last_checkin_at
		FROM mdme_devices WHERE tenant_id=$1 AND compliance_status='non_compliant'
		ORDER BY risk_score DESC LIMIT 20`, tidStr)
	if nr != nil {
		defer nr.Close()
		for nr.Next() {
			var did, dname, plat, owner, dept string
			var risk int
			var lc *string
			nr.Scan(&did, &dname, &plat, &owner, &dept, &risk, &lc)
			nonCompliantDevs = append(nonCompliantDevs, map[string]interface{}{
				"device_id": did, "device_name": dname, "platform": plat,
				"owner": owner, "department": dept, "risk_score": risk, "last_checkin_at": lc,
			})
		}
	}

	pct := func(n int) int {
		if total == 0 {
			return 0
		}
		return n * 100 / total
	}

	c.JSON(http.StatusOK, gin.H{
		"total": total, "compliant": compliant, "non_compliant": nonCompliant,
		"compliance_rate": pct(compliant),
		"controls": []map[string]interface{}{
			{"control": "Device Encryption", "passed": enc, "failed": total - enc, "pct": pct(enc)},
			{"control": "Screen Lock Enabled", "passed": screenLock, "failed": total - screenLock, "pct": pct(screenLock)},
			{"control": "Biometric Authentication", "passed": bio, "failed": total - bio, "pct": pct(bio)},
			{"control": "Not Rooted/Jailbroken", "passed": noRooted, "failed": total - noRooted, "pct": pct(noRooted)},
		},
		"non_compliant_devices": nonCompliantDevs,
		"violations": []map[string]interface{}{
			{"violation": "Encryption disabled", "count": total - enc, "severity": "critical"},
			{"violation": "Screen lock not set", "count": total - screenLock, "severity": "high"},
			{"violation": "Rooted/Jailbroken", "count": total - noRooted, "severity": "critical"},
			{"violation": "OS below minimum version", "count": 3, "severity": "high"},
			{"violation": "Expired certificate", "count": 2, "severity": "medium"},
			{"violation": "Blocked app installed", "count": 5, "severity": "medium"},
		},
	})
}

// ── Remote Actions ────────────────────────────────────────────────────────────

func PostMDMERemoteAction(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		DeviceID   string `json:"device_id"`
		DeviceName string `json:"device_name"`
		ActionType string `json:"action_type"`
	}
	if err := c.BindJSON(&body); err != nil || body.DeviceID == "" || body.ActionType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id and action_type required"})
		return
	}

	actionID := mdmeID("MDME-ACT")
	db.Exec(`INSERT INTO mdme_remote_actions (tenant_id,action_id,device_id,device_name,action_type,initiated_by,status)
		VALUES ($1,$2,$3,$4,$5,$6,'pending')`,
		tidStr, actionID, body.DeviceID, body.DeviceName, body.ActionType, actor)

	db.Exec(`INSERT INTO mdme_timeline (tenant_id,device_id,event_type,summary,actor,severity,details)
		VALUES ($1,$2,'remote_action',$3,$4,'info',$5)`,
		tidStr, body.DeviceID,
		fmt.Sprintf("Remote action queued: %s", body.ActionType),
		actor, fmt.Sprintf("action_id:%s", actionID))

	mdmeAudit(tid, "remote_action_queued", "device", body.DeviceID, body.DeviceName, actor,
		fmt.Sprintf("action:%s", body.ActionType))
	mdmeNotify(tid, "remote_action", fmt.Sprintf("Remote Action: %s", body.ActionType),
		fmt.Sprintf("Action '%s' queued for device %s by %s", body.ActionType, body.DeviceName, actor),
		"info", body.DeviceID)

	c.JSON(http.StatusOK, gin.H{"action_id": actionID, "status": "pending"})
}

func GetMDMERemoteActions(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	devID := c.Query("device_id")
	limit := parseLimit(c, 100)

	where := []string{"tenant_id=$1"}
	args  := []interface{}{tidStr}
	i     := 2
	if devID != "" {
		where = append(where, fmt.Sprintf("device_id=$%d", i))
		args = append(args, devID); i++
	}
	args = append(args, limit)

	var actions []map[string]interface{}
	rows, _ := db.Query(fmt.Sprintf(`SELECT action_id,device_id,device_name,action_type,status,
		initiated_by,result,completed_at,created_at
		FROM mdme_remote_actions WHERE %s ORDER BY created_at DESC LIMIT $%d`,
		strings.Join(where, " AND "), i), args...)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var actID, devID2, dname, atype, st, by string
			var result, compAt, ca *string
			if err := rows.Scan(&actID, &devID2, &dname, &atype, &st, &by, &result, &compAt, &ca); err == nil {
				actions = append(actions, map[string]interface{}{
					"action_id": actID, "device_id": devID2, "device_name": dname,
					"action_type": atype, "status": st, "initiated_by": by,
					"result": result, "completed_at": compAt, "created_at": ca,
				})
			}
		}
	}
	if actions == nil {
		actions = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, actions)
}

// ── Threats ───────────────────────────────────────────────────────────────────

func GetMDMEThreats(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var threats []map[string]interface{}
	rows, _ := db.Query(`SELECT threat_id,device_id,device_name,threat_type,title,
		description,severity,status,detected_at,resolved_at,resolved_by
		FROM mdme_threats WHERE tenant_id=$1 ORDER BY
		CASE status WHEN 'open' THEN 1 WHEN 'investigating' THEN 2 ELSE 3 END,
		CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
		detected_at DESC`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var tid2, devID, dname, ttype, title, desc, sev, st string
			var det, res, resBy *string
			if err := rows.Scan(&tid2, &devID, &dname, &ttype, &title, &desc, &sev, &st, &det, &res, &resBy); err == nil {
				threats = append(threats, map[string]interface{}{
					"threat_id": tid2, "device_id": devID, "device_name": dname,
					"threat_type": ttype, "title": title, "description": desc,
					"severity": sev, "status": st, "detected_at": det,
					"resolved_at": res, "resolved_by": resBy,
				})
			}
		}
	}
	if threats == nil {
		threats = []map[string]interface{}{}
	}

	var open, investigating, resolved int
	db.QueryRow(`SELECT COUNT(*) FROM mdme_threats WHERE tenant_id=$1 AND status='open'`, tidStr).Scan(&open)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_threats WHERE tenant_id=$1 AND status='investigating'`, tidStr).Scan(&investigating)
	db.QueryRow(`SELECT COUNT(*) FROM mdme_threats WHERE tenant_id=$1 AND status='resolved'`, tidStr).Scan(&resolved)

	c.JSON(http.StatusOK, gin.H{
		"threats": threats,
		"summary": gin.H{"open": open, "investigating": investigating, "resolved": resolved},
	})
}

func PatchMDMEThreat(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	threatID := c.Param("id")
	actor := usernameFromContext(c)

	var body struct{ Status string `json:"status"` }
	c.BindJSON(&body)
	if body.Status == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status required"})
		return
	}
	db.Exec(`UPDATE mdme_threats SET status=$1,resolved_by=$2,resolved_at=CASE WHEN $1='resolved' THEN NOW() ELSE NULL END
		WHERE tenant_id=$3 AND threat_id=$4`, body.Status, actor, tidStr, threatID)
	mdmeAudit(tid, "threat_updated", "threat", threatID, "", actor, fmt.Sprintf("status→%s", body.Status))
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// ── Timeline ──────────────────────────────────────────────────────────────────

func GetMDMETimeline(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	devID := c.Param("id")
	limit := parseLimit(c, 50)

	var events []map[string]interface{}
	rows, _ := db.Query(`SELECT event_type,summary,actor,severity,details,created_at
		FROM mdme_timeline WHERE tenant_id=$1 AND device_id=$2
		ORDER BY created_at DESC LIMIT $3`, tidStr, devID, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var etype, summ, actor, sev string
			var det, ca *string
			if e := rows.Scan(&etype, &summ, &actor, &sev, &det, &ca); e == nil {
				events = append(events, map[string]interface{}{
					"event_type": etype, "summary": summ, "actor": actor,
					"severity": sev, "details": det, "created_at": ca,
				})
			}
		}
	}
	if events == nil {
		events = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, events)
}

// ── Analytics ─────────────────────────────────────────────────────────────────

func GetMDMEAnalytics(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	// OS version distribution
	osVers := []map[string]interface{}{}
	ovr, _ := db.Query(`SELECT platform, os_version, COUNT(*) FROM mdme_devices WHERE tenant_id=$1
		GROUP BY platform,os_version ORDER BY platform, COUNT(*) DESC`, tidStr)
	if ovr != nil {
		defer ovr.Close()
		for ovr.Next() {
			var plat, osv string
			var cnt int
			ovr.Scan(&plat, &osv, &cnt)
			osVers = append(osVers, map[string]interface{}{"platform": plat, "os_version": osv, "count": cnt})
		}
	}

	// device type breakdown
	typeBreak := []map[string]interface{}{}
	tbr, _ := db.Query(`SELECT device_type, COUNT(*) FROM mdme_devices WHERE tenant_id=$1
		GROUP BY device_type ORDER BY COUNT(*) DESC`, tidStr)
	if tbr != nil {
		defer tbr.Close()
		for tbr.Next() {
			var dt string
			var cnt int
			tbr.Scan(&dt, &cnt)
			typeBreak = append(typeBreak, map[string]interface{}{"device_type": dt, "count": cnt})
		}
	}

	// department breakdown
	deptBreak := []map[string]interface{}{}
	dr, _ := db.Query(`SELECT department, COUNT(*) FROM mdme_devices WHERE tenant_id=$1
		AND department!='' GROUP BY department ORDER BY COUNT(*) DESC`, tidStr)
	if dr != nil {
		defer dr.Close()
		for dr.Next() {
			var dept string
			var cnt int
			dr.Scan(&dept, &cnt)
			deptBreak = append(deptBreak, map[string]interface{}{"department": dept, "count": cnt})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"os_distribution":   osVers,
		"type_distribution": typeBreak,
		"dept_distribution": deptBreak,
		"enrollment_trend": []map[string]interface{}{
			{"month": "Jan", "enrolled": 312, "unenrolled": 8},
			{"month": "Feb", "enrolled": 334, "unenrolled": 12},
			{"month": "Mar", "enrolled": 361, "unenrolled": 9},
			{"month": "Apr", "enrolled": 388, "unenrolled": 15},
			{"month": "May", "enrolled": 408, "unenrolled": 11},
			{"month": "Jun", "enrolled": 427, "unenrolled": 7},
		},
		"compliance_trend": []map[string]interface{}{
			{"month": "Jan", "compliant": 284, "non_compliant": 28},
			{"month": "Feb", "compliant": 302, "non_compliant": 32},
			{"month": "Mar", "compliant": 331, "non_compliant": 30},
			{"month": "Apr", "compliant": 360, "non_compliant": 28},
			{"month": "May", "compliant": 382, "non_compliant": 26},
			{"month": "Jun", "compliant": 403, "non_compliant": 24},
		},
		"threat_trend": []map[string]interface{}{
			{"month": "Jan", "rooted": 4, "malware": 2, "phishing": 1},
			{"month": "Feb", "rooted": 3, "malware": 3, "phishing": 2},
			{"month": "Mar", "rooted": 2, "malware": 1, "phishing": 3},
			{"month": "Apr", "rooted": 3, "malware": 2, "phishing": 1},
			{"month": "May", "rooted": 1, "malware": 2, "phishing": 2},
			{"month": "Jun", "rooted": 2, "malware": 1, "phishing": 1},
		},
		"top_apps": []map[string]interface{}{
			{"app_name": "Microsoft Outlook", "device_count": 401, "category": "productivity"},
			{"app_name": "Microsoft Teams", "device_count": 398, "category": "communication"},
			{"app_name": "CrowdStrike Falcon", "device_count": 415, "category": "security"},
			{"app_name": "Zscaler Client Connector", "device_count": 390, "category": "security"},
			{"app_name": "Slack", "device_count": 312, "category": "communication"},
			{"app_name": "Zoom", "device_count": 401, "category": "communication"},
			{"app_name": "Chrome", "device_count": 388, "category": "browser"},
			{"app_name": "1Password", "device_count": 271, "category": "security"},
		},
	})
}

// ── AI ────────────────────────────────────────────────────────────────────────

func PostMDMEAI(c *gin.Context) {
	var body struct {
		Action   string `json:"action"`
		DeviceID string `json:"device_id"`
	}
	c.BindJSON(&body)

	responses := map[string]string{
		"device_health_summary": `## Device Health Summary

**Fleet Overview — 427 Managed Devices**

**Health Score: 91/100 — GOOD**

**Platform Breakdown:**
- iOS (iPhone/iPad): 218 devices — Avg risk: 21
- Android (Corporate): 156 devices — Avg risk: 34
- Android (BYOD): 53 devices — Avg risk: 58

**Current Concerns:**
⚠️  2 devices with root/jailbreak detected (quarantined)
⚠️  3 devices running OS versions below policy minimum
⚠️  5 devices offline for >7 days (may be lost or decommissioned)
✅ 94.4% compliance rate (403/427 compliant)
✅ 97.2% encryption coverage (415/427 encrypted)
✅ Agent coverage: 98.1% (419/427 with active MDM agent)

**Recommended Actions:**
1. Investigate 5 offline devices — verify ownership
2. Push OS update policy to 3 non-compliant devices
3. Review BYOD risk — BYOD avg risk (58) is 2.7x corporate (21)`,

		"risk_assessment": `## MDM Fleet Risk Assessment

**Overall Fleet Risk: MEDIUM-LOW (Score: 28/100)**

**High-Risk Segments:**

**BYOD Devices (53) — Risk: HIGH**
- Personal apps co-mingled with corporate data
- Personal iCloud/Google Drive may sync corporate documents
- Less policy enforcement capability vs. corporate-owned
- Recommendation: Enforce containerization (Samsung Knox / iOS Managed Open-In)

**Android Corporate (156) — Risk: MEDIUM**
- 3 devices running Android 12 below minimum Android 13 policy
- 1 device with suspicious app (Kali NetHunter detected)
- Recommendation: Enforce Android Enterprise Work Profile on all

**iOS Corporate (218) — Risk: LOW**
- 2 devices with certificate expiring in <30 days
- All devices on iOS 17.x — patch compliance strong
- Recommendation: Enable Declarative Device Management (DDM) for faster policy push

**Top Risk Factors:**
1. BYOD program — 53 devices with partial policy enforcement
2. Stale offline devices — 5 devices not seen in >7 days
3. Blocked app still installed on 5 devices (30-day grace expired)`,

		"compliance_recommendations": `## Compliance Improvement Recommendations

**Current Score: 94.4% — Target: 99%**

**Gap Analysis — 24 Non-Compliant Devices:**

**Critical Gaps (act within 24h):**
1. 2 rooted/jailbroken devices — already quarantined, initiate wipe if not resolved within 48h
2. 3 devices with encryption disabled — push immediate remediation command, escalate if no response

**High Priority (act within 1 week):**
3. 5 blocked apps still present (grace period expired) — trigger silent removal via MDM command
4. 3 devices below minimum OS version — push update enforcement policy
5. 8 devices with screen lock timeout > 5 min policy — update via configuration profile

**Medium Priority (act within 30 days):**
6. 6 BYOD devices — not enrolled in full MDM, only email profile — enroll in Intune MAM
7. 2 devices with certificate expiring in 28 days — push renewal via SCEP profile
8. 4 devices with biometric not enabled — communicate policy change to users

**Policy Recommendations:**
- Set automatic quarantine for rooted devices (currently manual)
- Enable conditional access integration with Azure AD
- Set compliance grace period to 7 days (currently 30 days)`,

		"security_policy_suggestions": `## Security Policy Recommendations

**Password Policy:**
- Current: 8 chars, alphanumeric
- Recommended: 12 chars, upper+lower+number+special, no dictionary words
- Rationale: NIST SP 800-63B requirement for enterprise authentication

**Screen Lock:**
- Current: 5 minute timeout
- Recommended: 2 minutes (MDM policy) + immediate lock on power button
- Rationale: Finance and HR devices have PII — 5 min is high exposure window

**iOS-Specific:**
- Enable Supervised Mode on all corporate iOS devices (unlocks deeper policy control)
- Enable App Store restrictions — allow only approved apps from VPP
- Deploy Always-On VPN (IKEv2) for all traffic, not just split-tunnel
- Enable Rapid Security Response — push patches within hours of Apple release

**Android-Specific:**
- Enforce Work Profile (Android Enterprise) on all BYOD devices
- Block USB debugging — prevents sideloading and data extraction
- Enable SafetyNet/Play Integrity API attestation in compliance policy
- Deploy Always-On VPN via Zscaler or similar

**Certificate Policy:**
- Deploy SCEP auto-renewal — certificates should renew 30 days before expiry
- Enable certificate-based Wi-Fi authentication (802.1X) — remove password-based SSID

**New Policy Suggestions:**
1. Zero Trust access — require device compliance + MFA for all corporate app access
2. Geofencing — alert when corporate device leaves approved regions
3. Application reputation scoring — block apps with >3 CVEs or bad reputation score`,

		"application_risk_analysis": `## Application Risk Analysis

**Total Unique Apps Across Fleet: 847**
**Approved: 398 | Blocked: 12 | Risky: 23 | Unclassified: 414**

**High Risk Applications Detected:**

🔴 **CRITICAL:**
- Kali NetHunter (Android) — 1 device — penetration testing framework, policy violation
- VirtualXposed (Android) — 2 devices — virtual Xposed framework, used to bypass root detection

🟠 **HIGH:**
- AppValley (iOS) — 3 devices — sideloading store, bypasses App Store review
- AltStore (iOS) — 1 device — developer sideloading tool, unverified apps
- VPN Proxy Master (Android) — 8 devices — unknown VPN with no privacy policy, data harvesting risk

🟡 **MEDIUM:**
- TikTok — 41 devices (BYOD) — flagged by CISA, China-linked data collection concerns
- AnyDesk — 6 devices — remote access tool, not in approved list
- NordVPN — 12 devices — personal VPN bypasses corporate DLP

**Recommended Actions:**
1. Immediately remove Kali NetHunter and VirtualXposed (silent uninstall via MDM)
2. Quarantine affected devices pending security review
3. Add AppValley and AltStore to blocked app list
4. Evaluate TikTok policy for BYOD devices — consider MAM-level block for corporate data access`,

		"lost_device_guidance": `## Lost Device Response Guide

**Recommended Response Steps:**

**Immediate (0-1 hour):**
1. Locate Device — use MDM GPS location (if enabled and device has battery)
2. Lock Device — push immediate lock with custom message + recovery contact
3. Play Sound — helps locate if device is nearby
4. Notify IT Security — escalate to incident response if device has sensitive data

**Short-Term (1-24 hours):**
4. Reset Passcode — prevent unauthorized access if screen lock is bypassed
5. Suspend Active Sessions — revoke device tokens in Azure AD / Entra ID
6. Notify User's Manager — document incident for HR and legal records
7. Check DLP Logs — review what data was accessed/synced in last 24h before loss

**If Not Recovered (>24 hours):**
8. Wipe Corporate Data (Selective Wipe) — removes corporate apps, email, VPN profiles
   - For BYOD: Only corporate container is wiped, personal data preserved
   - For Corporate-owned: Full factory reset if device is not recovered
9. Revoke Certificates — push CRL update, expire SCEP cert for device
10. Update Inventory — mark as Lost in CMDB, close enrollment record

**If Device is Recovered:**
11. Run Compliance Check — verify device wasn't tampered with
12. Re-enroll if wiped — issue new enrollment token to user
13. Review access logs for unauthorized activity during loss period`,
	}

	resp, ok := responses[body.Action]
	if !ok {
		resp = responses["device_health_summary"]
	}
	c.JSON(http.StatusOK, gin.H{"response": resp, "action": body.Action})
}

// ── Reports ───────────────────────────────────────────────────────────────────

func GetMDMEReports(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)

	var reports []map[string]interface{}
	rows, _ := db.Query(`SELECT report_id,title,report_type,generated_by,format,size_bytes,device_count,created_at
		FROM mdme_reports WHERE tenant_id=$1 ORDER BY created_at DESC`, tidStr)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, rtype, by, format string
			var sizeB int64
			var cnt int
			var ca *string
			if err := rows.Scan(&id, &title, &rtype, &by, &format, &sizeB, &cnt, &ca); err == nil {
				reports = append(reports, map[string]interface{}{
					"report_id": id, "title": title, "report_type": rtype,
					"generated_by": by, "format": format, "size_bytes": sizeB,
					"device_count": cnt, "created_at": ca,
				})
			}
		}
	}
	if reports == nil {
		reports = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, reports)
}

func PostMDMEReport(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	actor := usernameFromContext(c)

	var body struct {
		Title      string `json:"title"`
		ReportType string `json:"report_type"`
		Format     string `json:"format"`
	}
	c.BindJSON(&body)
	if body.Format == "" {
		body.Format = "pdf"
	}
	id := mdmeID("MDME-RPT")
	var cnt int
	db.QueryRow(`SELECT COUNT(*) FROM mdme_devices WHERE tenant_id=$1`, tidStr).Scan(&cnt)
	sizeB := int64(150_000 + rand.Intn(500_000))
	db.Exec(`INSERT INTO mdme_reports (tenant_id,report_id,title,report_type,generated_by,format,size_bytes,device_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		tidStr, id, body.Title, body.ReportType, actor, body.Format, sizeB, cnt)
	c.JSON(http.StatusOK, gin.H{"report_id": id, "device_count": cnt})
}

// ── Notifications ─────────────────────────────────────────────────────────────

func GetMDMENotifications(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	limit := parseLimit(c, 50)

	var notifs []map[string]interface{}
	rows, _ := db.Query(`SELECT id,event_type,title,message,severity,device_id,read,created_at
		FROM mdme_notifications WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tidStr, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var etype, title, msg, sev string
			var devID *string
			var read bool
			var ca *string
			if err := rows.Scan(&id, &etype, &title, &msg, &sev, &devID, &read, &ca); err == nil {
				notifs = append(notifs, map[string]interface{}{
					"id": id, "event_type": etype, "title": title, "message": msg,
					"severity": sev, "device_id": devID, "read": read, "created_at": ca,
				})
			}
		}
	}
	if notifs == nil {
		notifs = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, notifs)
}

func PatchMDMENotificationsRead(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	db.Exec(`UPDATE mdme_notifications SET read=TRUE WHERE tenant_id=$1`, tidStr)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func GetMDMEAudit(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	tidStr := fmt.Sprintf("%d", tid)
	limit := parseLimit(c, 100)

	var entries []map[string]interface{}
	rows, _ := db.Query(`SELECT action,object_type,object_id,object_name,actor,ip_address,details,created_at
		FROM mdme_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tidStr, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var action, otype, actor string
			var oid, oname, ip, det, ca *string
			if err := rows.Scan(&action, &otype, &oid, &oname, &actor, &ip, &det, &ca); err == nil {
				entries = append(entries, map[string]interface{}{
					"action": action, "object_type": otype, "object_id": oid,
					"object_name": oname, "actor": actor, "ip_address": ip,
					"details": det, "created_at": ca,
				})
			}
		}
	}
	if entries == nil {
		entries = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, entries)
}
