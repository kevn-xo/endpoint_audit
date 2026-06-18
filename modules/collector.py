"""
collector.py - All data gathering for endpoint audit.
Each function is independently callable and returns a clean dict/list.
"""

import os, socket, json, psutil, wmi, winreg
import win32service, win32security, win32net, win32con
from datetime import datetime

HIVE_MAP = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
}

UNINSTALL_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]

STATE_MAP = {
    1:"STOPPED", 2:"START_PENDING", 3:"STOP_PENDING",
    4:"RUNNING",  5:"CONTINUE_PENDING", 6:"PAUSE_PENDING", 7:"PAUSED"
}


def collect_system_metadata():
    c       = wmi.WMI()
    os_info = c.Win32_OperatingSystem()[0]
    cs_info = c.Win32_ComputerSystem()[0]
    disks   = []
    for part in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(part.mountpoint)
            disks.append({"device": part.device, "mountpoint": part.mountpoint,
                          "total_gb": round(u.total/1e9,2),
                          "used_gb":  round(u.used/1e9,2),
                          "free_gb":  round(u.free/1e9,2),
                          "percent":  u.percent})
        except: pass
    users = [{"name":u.name,"terminal":u.terminal,"host":u.host}
             for u in psutil.users()]
    return {
        "hostname":        socket.gethostname(),
        "ip_address":      socket.gethostbyname(socket.gethostname()),
        "os_name":         os_info.Caption,
        "os_version":      os_info.Version,
        "os_arch":         os_info.OSArchitecture,
        "domain":          cs_info.Domain,
        "last_boot":       os_info.LastBootUpTime[:14],
        "total_ram_gb":    round(int(os_info.TotalVisibleMemorySize)/1024/1024,2),
        "free_ram_gb":     round(int(os_info.FreePhysicalMemory)/1024/1024,2),
        "disks":           disks,
        "logged_on_users": users,
        "audit_time":      datetime.now().isoformat(),
    }


def collect_processes(suspicious_paths=None, suspicious_names=None):
    suspicious_paths = suspicious_paths or []
    suspicious_names = [n.lower() for n in (suspicious_names or [])]
    processes        = []
    for proc in psutil.process_iter([
        "pid","name","exe","cmdline","ppid",
        "username","memory_info","create_time","status"
    ]):
        try:
            info  = proc.info
            exe   = info.get("exe") or ""
            name  = info.get("name") or ""
            flags, risk = [], 0
            if name.lower() in suspicious_names:
                flags.append("KNOWN_MALICIOUS_NAME"); risk += 8
            for sp in suspicious_paths:
                if sp.lower() in exe.lower():
                    flags.append(f"SUSPICIOUS_PATH:{sp}"); risk += 5; break
            if exe and not os.path.exists(exe):
                flags.append("EXE_NOT_ON_DISK"); risk += 6
            try:
                parent_name = psutil.Process(info["ppid"]).name()
            except: parent_name = "unknown"
            mem    = info.get("memory_info")
            ram_mb = round(mem.rss/1024/1024,2) if mem else 0
            try:
                ct = datetime.fromtimestamp(info["create_time"]).strftime("%Y-%m-%d %H:%M:%S")
            except: ct = "unknown"
            processes.append({
                "pid":info["pid"],"name":name,"exe":exe,
                "cmdline":" ".join(info.get("cmdline") or []),
                "ppid":info["ppid"],"parent_name":parent_name,
                "username":info.get("username") or "N/A",
                "ram_mb":ram_mb,"status":info.get("status"),
                "create_time":ct,"risk_score":risk,"flags":flags,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied): pass
    processes.sort(key=lambda x: x["risk_score"], reverse=True)
    return processes


def collect_services(suspicious_paths=None):
    suspicious_paths = suspicious_paths or []
    services, scm   = [], None
    try:
        scm = win32service.OpenSCManager(
            None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
        raw = win32service.EnumServicesStatus(
            scm, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL)
        for name, display_name, status in raw:
            state  = STATE_MAP.get(status[1], "UNKNOWN")
            flags, risk = [], 0
            try:
                sh  = win32service.OpenService(
                    scm, name, win32service.SERVICE_QUERY_CONFIG)
                cfg = win32service.QueryServiceConfig(sh)
                win32service.CloseServiceHandle(sh)
                start_mode  = {2:"Auto",3:"Manual",4:"Disabled"}.get(cfg[1],str(cfg[1]))
                binary_path = cfg[3] or ""
                svc_acct    = cfg[7] or ""
                for sp in suspicious_paths:
                    if sp.lower() in binary_path.lower():
                        flags.append(f"SUSPICIOUS_PATH:{sp}"); risk += 5; break
                if start_mode=="Auto" and state=="STOPPED":
                    flags.append("AUTO_START_BUT_STOPPED"); risk += 3
            except:
                start_mode = binary_path = svc_acct = "N/A"
            services.append({
                "name":name,"display_name":display_name,"state":state,
                "start_mode":start_mode,"binary_path":binary_path,
                "service_acct":svc_acct,"risk_score":risk,"flags":flags,
            })
    finally:
        if scm: win32service.CloseServiceHandle(scm)
    services.sort(key=lambda x: x["risk_score"], reverse=True)
    return services


def collect_startup_keys(reg_key_configs=None):
    reg_key_configs = reg_key_configs or []
    entries         = []
    for kc in reg_key_configs:
        hive = HIVE_MAP.get(kc["hive"])
        if not hive: continue
        try:
            key = winreg.OpenKey(hive, kc["path"])
            try:
                idx = 0
                while True:
                    try:
                        vname, data, _ = winreg.EnumValue(key, idx)
                        raw_path  = (data.strip('"').split('"')[0].split()[0]
                                     if data else "")
                        exe_exists = os.path.exists(raw_path) if raw_path else False
                        flags, risk = [], 0
                        if not exe_exists and raw_path:
                            flags.append("EXE_NOT_ON_DISK"); risk += 6
                        for loc in ["\\Temp\\","\\AppData\\","\\Public\\"]:
                            if loc.lower() in raw_path.lower():
                                flags.append(f"SUSPICIOUS_PATH:{loc}"); risk += 5; break
                        entries.append({
                            "hive":kc["hive"],"key_path":kc["path"],
                            "value_name":vname,"value_data":data,
                            "exe_path":raw_path,"exe_exists":exe_exists,
                            "risk_score":risk,"flags":flags,
                        })
                        idx += 1
                    except OSError: break
            finally: key.Close()
        except FileNotFoundError: pass
    entries.sort(key=lambda x: x["risk_score"], reverse=True)
    return entries


def collect_local_admins():
    admins = []
    try:
        members, _, _ = win32net.NetLocalGroupGetMembers(
            None, "Administrators", 1)
        for m in members:
            try:
                sid, domain, _ = win32security.LookupAccountName(None, m["name"])
                sid_str = win32security.ConvertSidToStringSid(sid)
            except:
                sid_str = "lookup_failed"; domain = "unknown"
            admins.append({"name":m["name"],"domain":domain,"sid":sid_str})
    except Exception as e:
        admins.append({"error":str(e)})
    return admins


def collect_network_connections():
    conns, pid_map = [], {}
    for proc in psutil.process_iter(["pid","name","exe"]):
        try: pid_map[proc.pid] = {"name":proc.info["name"],"exe":proc.info["exe"] or ""}
        except: pass
    for c in psutil.net_connections(kind="inet"):
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        pi    = pid_map.get(c.pid, {"name":"unknown","exe":""})
        flags = []
        if c.raddr and c.status == "ESTABLISHED":
            rip = c.raddr.ip
            if not any(rip.startswith(p) for p in
                       ["127.","10.","192.168.","172."]):
                flags.append("EXTERNAL_CONNECTION")
        conns.append({
            "pid":c.pid,"process":pi["name"],"exe":pi["exe"],
            "type":"TCP" if c.type==1 else "UDP",
            "local":laddr,"remote":raddr,"status":c.status,"flags":flags,
        })
    conns.sort(key=lambda x: len(x["flags"]), reverse=True)
    return conns


def collect_installed_software():
    software, seen = [], set()
    for hive, path in UNINSTALL_PATHS:
        try:
            key = winreg.OpenKey(hive, path)
            try:
                idx = 0
                while True:
                    try:
                        sk_name = winreg.EnumKey(key, idx)
                        try:
                            sk = winreg.OpenKey(key, sk_name)
                            try:
                                def qv(k,n,d=""):
                                    try: v,_=winreg.QueryValueEx(k,n); return str(v)
                                    except: return d
                                dn = qv(sk,"DisplayName")
                                if not dn or dn in seen:
                                    idx+=1; continue
                                seen.add(dn)
                                software.append({
                                    "name":dn,
                                    "version":qv(sk,"DisplayVersion"),
                                    "vendor":qv(sk,"Publisher"),
                                    "install_date":qv(sk,"InstallDate"),
                                    "uninstall":qv(sk,"UninstallString"),
                                })
                            finally: sk.Close()
                        except: pass
                        idx += 1
                    except OSError: break
            finally: key.Close()
        except FileNotFoundError: pass
    software.sort(key=lambda x: x.get("install_date") or "0", reverse=True)
    return software
