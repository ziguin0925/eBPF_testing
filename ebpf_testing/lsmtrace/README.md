# lsmtrace

Trace all Linux Security Modules hooks touched by executable. 
Have a look at my **[blog post](https://lumontec.com/1-building-a-security-tracing)** to find out more.

![image](https://github.com/ziguin0925/web_1/assets/117524772/12f2e96d-d2fd-4abe-9f82-a33f3490af24)



### Verifying BPF LSM Availability


First, please confirm that your kernel version is higher than 5.7. Next, you can use the following command to check if BPF LSM support is enabled:
```
$ cat /boot/config-$(uname -r) | grep BPF_LSM
CONFIG_BPF_LSM=y
```


If the output contains CONFIG_BPF_LSM=y, BPF LSM is supported. Provided that the above conditions are met, you can use the following command to check if the output includes the bpf option:
```
$ cat /sys/kernel/security/lsm
ndlock,lockdown,yama,integrity,apparmor
```


If the output does not include the bpf option (as in the example above), you can modify /etc/default/grub:
```
GRUB_CMDLINE_LINUX="lsm=ndlock,lockdown,yama,integrity,apparmor,bpf"
```
Then, update the grub configuration using the update-grub2 command (the corresponding command may vary depending on the system), and restart the system.


* [eunomia]](https://eunomia.dev/tutorials/19-lsm-connect/)




### How to send permossion dinied

원하는 lsm 함수 위치에 eBPF프로그램을 연결하여 return값으로 EPERM을 부여.(EPERM = -1)


**e.g.**
```
SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // Satisfying "cannot override a denial" rule
    if (ret != 0)
    {
        return ret;
    }

    // Only IPv4 in this example
    if (address->sa_family != AF_INET)
    {
        return 0;
    }

    // Cast the address to an IPv4 socket address
    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    // Where do you want to go?
    __u32 dest = addr->sin_addr.s_addr;
    bpf_printk("lsm: found connect to %d", dest);

    if (dest == blockme)
    {
        bpf_printk("lsm: blocking %d", dest);
        return -EPERM;
    }
    return 0;
}
```
[eunomia]](https://eunomia.dev/tutorials/19-lsm-connect/#writing-ebpf-programs)
 
 
## Requirements

Your kernel must have been compiled with the follwing options:
* BPF_SYSCALL
* BPF_LSM
* DEBUG_INFO
* DEBUG_INFO_BTF


```
cat /boot/config-$(uname -r)
```


## Compilation

```shell
$ cd src
$ make
```

If there is a problem, change the version of libbpf directory or bpftool.


## Run

```shell
$ sudo ./lsmtrace /usr/bin/ls -a /home  

Attaching hooks, don`t rush..

-> HOOK_CALL: -> cred_getsecid( const struct cred *c, u32 *secid )
-> HOOK_CALL: -> file_permission( struct file *file, int mask )
     file,f_mode = 32797
     file,f_path.dentry,d_flags = 64
     file,f_path.dentry,d_name.name = ls
     file,f_path.dentry,d_inode,i_ino = 3670696
...
```


## RG_code

eBPF lsm hook에서 task_getsecid를 task_getsecid_obj로 변환, lsm/sb_add_mnt_opt주석 처리

RG_code/bpf_dump_helper.h 에서 mount, dentry의 정보를 읽어 현재 파일부터 루트까지의 경로를 읽음. 

RG_code/lsmtrace.bpf.c 의 경우 file open에서  RG_code/bpf_dump_helper.h 의 함수를 불러 읽어 디렉터리 탐색 후 해당 hook 포인트에 맵을 통해 EPERM 전송.

inode_rename에 EPERM추가, file_open에 EPERM추가.

ftrace를 통해 call graph 확인.
계층적으로 불러지는 커널 함수 순서대로 데이터 전달이 중요.

![image](https://github.com/ziguin0925/web_1/assets/117524772/9ca05bb0-eb1c-457a-819c-fa5ac753b825)
