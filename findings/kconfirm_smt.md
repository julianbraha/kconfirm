# Linux Patches from Development and Usage of kconfirm-smt

## Kconfig Language / Interpreter
### int/hex validation bugs:
1. https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=54f11924e4854177b357af499ebc447dc8c3c590 
2. https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=a5e84d6f6df1fdb64c06fdb64894199aaf5ec899 
### int/hex unspecified semantics:
1. https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=d13bad83d89d1022fee254c08f6e01084eb4395e 
2. https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=9b8719973ee2c5ec23aab9b958e5c6fbdf352f90 
3. https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=f9f31f5f13b5e5459e2d3322fe6b5e19d511919a 
## Kconfig Language Usage
### Unmet dependency bugs:
1. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e920c36f2073d533bdf19ba6ab690432c8173b63
2. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=95a99456ff354a1bad4b4032ed1d044d608bd438
3. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fc03f930bd9fd7c09617e41b1743e50ba659707c
4. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3667bc164849fee4f1b18b182bdfe643f758ca17
5. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aaa5be0258db1709e254b4150af5c2fa5518c548
6. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=46840fa8c9f53b9c90db4b4be2b808bbc626cde2 
   - This patch fixes 4 unmet dependency bugs
7. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a2fd5a9f09587eddf4d96c7b46541359985c6ea8
8. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5859fa79c7d85d0c242a9a1ffb40bab9732d4ef1
9. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=72cc574aa3791aa4f05d247b4e884cdbd135819a 
   - This patch fixes 2 unmet dependency bugs

10. https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=1179929b3abd4adb6ca7fae91d649c64a7293aca 
11. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fb5a08026a68be0ec5f660588311fb1091bf5d58 
    - This patch fixes 3 unmet dependency bugs
12. https://lore.kernel.org/all/20261020222817.1231643-1-julianbraha@gmail.com/

**Dead subrange:**
1. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6903878d4654bdef4e08e38cdf1ae306ce7de5f9 

**Out-of-range default:**
1. https://lore.kernel.org/all/20261014125553.2280686-1-julianbraha@gmail.com/ 

**int/hex/string options used as expression operands:**
1. https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=8cdae75cebe06b8abea9cd3402442d47cf50b485 
   - This patch fixes 2 instances

**select-choice:**
1. https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=35abc3cd8ab65dd7d07d4fc48a0d7048ce47d055
2. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1e6be4bd53f0f06377c3ce3c26ea4a6cadd4ab46
3. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=09fbaddec89ebf3b6fa4b54271402186aa043a27
4. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=94d32f1ace8ee3ef3537ac6c8e71b76a418a4762
5. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d1917ccb7b6f830c0f0c3734bdc8af66a002a9af
6. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=b17006b45283f012a6e166517f5ca3e1af2f806a

**Wrong type:**
1. https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=456b17ccaaf313a65652e51a11884f669c7c3929 
   - This patch fixes 7 instances

**Dead/unreachable option:**
1. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=86ad6489e38c76c06c0b4a4229391a794023b5e0
