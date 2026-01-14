import os
import sys

import requests_mock

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)

from check_pve import CheckPVE, UnknownCheckError, CheckState

PAYLOAD_NODE_STATUS = {
    "loadavg": ["0.25", "0.24", "0.25"],
    "cpuinfo": {
        "sockets": 1,
        "cpus": 32,
        "mhz": "2100.000",
        "cores": 16,
        "model": "AMD EPYC 7281 16-Core Processor",
        "hvm": "1",
        "user_hz": 100,
        "flags": "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid amd_dcm aperfmperf pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw skinit wdt tce topoext perfctr_core perfctr_nb bpext perfctr_llc mwaitx cpb hw_pstate ssbd ibpb vmmcall fsgsbase bmi1 avx2 smep bmi2 rdseed adx smap clflushopt sha_ni xsaveopt xsavec xgetbv1 xsaves clzero irperf xsaveerptr arat npt lbrv svm_lock nrip_save tsc_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_vmsave_vmload vgif overflow_recov succor smca",
    },
    "uptime": 512739,
    "ksm": {"shared": 0},
    "rootfs": {
        "total": 96210518016,
        "used": 1453588480,
        "free": 94756929536,
        "avail": 94756929536,
    },
    "idle": 0,
    "wait": 0.000117821328967716,
    "pveversion": "pve-manager/7.1-8/5b267f33",
    "cpu": 0.00335136224619281,
    "swap": {"free": 0, "used": 0, "total": 0},
    "kversion": "Linux 5.13.19-2-pve #1 SMP PVE 5.13.19-4 (Mon, 29 Nov 2021 12:10:09 +0100)",
    "memory": {"total": 135051665408, "used": 106784067584, "free": 28267597824},
}


def pve_api_mockup(command: str, payload: dict, mocker: requests_mock.Mocker):
    pve = CheckPVE("pve.example.org")

    mocker.get(pve._get_url(command), json={"data": payload})

    return pve
