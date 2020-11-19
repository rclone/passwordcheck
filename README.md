# passwordcheck for rclone config files

In https://github.com/rclone/rclone/issues/4783 a security issue was
found which meant that passwords generated by "rclone config" might be
insecure.

This program checks your rclone config file for any of those
passwords.

## Installation

Download the relevant zip file for your OS and architecture from here:

- https://github.com/rclone/passwordcheck/releases

Unpack the zip archive - use `unzip archive.zip` on Linux/macOS - use
Explorer on Windows.

Open a terminal and change directory to the place you unpacked the zip
file.

First find where your rclone config file is.

```
 rclone config file
Configuration file is stored at:
/home/USER/.rclone.conf
```

Now run the utility with this as an argument

```
./passwordcheck /home/USER/.rclone.conf
```

Note that it may take 10 minutes or more to run. At the end it will
print a report showing any insecure passwords found.

For example:

```
$ ./passwordcheck ~/.rclone.conf
2020/11/19 14:01:49 Looking through 39103309 seeds from seed 1566691200 generated at 2019-08-25 01:00:00 to seed 1605794509 generated at 2020-11-19 14:01:49 for 3 passwords of length 64 bits
2020/11/19 14:03:38 FOUND match for remote test-remote-1: obscured password "fJKeinHaUgkd_4pO0J70tUMUkvoxoPES5p7-" at seed 1605788442 generated at 2020-11-19 12:20:42
2020/11/19 14:03:38 That took 1m48.992723504s for 358769.904475 seeds/s
2020/11/19 14:03:38 Looking through 39103309 seeds from seed 1566691200 generated at 2019-08-25 01:00:00 to seed 1605794509 generated at 2020-11-19 14:01:49 for 1 passwords of length 80 bits
2020/11/19 14:05:26 That took 1m48.506673926s for 360376.994199 seeds/s
2020/11/19 14:05:26 Looking through 39103309 seeds from seed 1566691200 generated at 2019-08-25 01:00:00 to seed 1605794509 generated at 2020-11-19 14:01:49 for 3 passwords of length 88 bits
2020/11/19 14:07:15 That took 1m48.705563639s for 359717.641775 seeds/s
2020/11/19 14:07:15 Looking through 39103309 seeds from seed 1566691200 generated at 2019-08-25 01:00:00 to seed 1605794509 generated at 2020-11-19 14:01:49 for 5 passwords of length 96 bits
2020/11/19 14:09:04 That took 1m48.960218306s for 358876.933324 seeds/s
2020/11/19 14:09:04 Looking through 39103309 seeds from seed 1566691200 generated at 2019-08-25 01:00:00 to seed 1605794509 generated at 2020-11-19 14:01:49 for 3 passwords of length 104 bits
2020/11/19 14:10:52 That took 1m48.214117167s for 361351.273047 seeds/s
2020/11/19 14:10:52 Looking through 39103309 seeds from seed 1566691200 generated at 2019-08-25 01:00:00 to seed 1605794509 generated at 2020-11-19 14:01:49 for 5 passwords of length 112 bits
2020/11/19 14:12:40 That took 1m48.342694733s for 360922.433177 seeds/s
2020/11/19 14:12:40 Looking through 39103309 seeds from seed 1566691200 generated at 2019-08-25 01:00:00 to seed 1605794509 generated at 2020-11-19 14:01:49 for 21 passwords of length 128 bits
2020/11/19 14:14:31 FOUND match for remote test-remote-2: obscured password "r-zxEh10ufF9r48najyPn9UrmECuMhWTkIsEubDKtZ3fehFHMwY" at seed 1605793125 generated at 2020-11-19 13:38:45
2020/11/19 14:14:31 FOUND match for remote test-remote-3: obscured password "px0py_poF8Jzis0rxNGf2OvtVZPnmwUruqI1o3trhE1I8fcR3To" at seed 1605793170 generated at 2020-11-19 13:39:30
2020/11/19 14:14:31 That took 1m50.446349362s for 354047.999104 seeds/s
2020/11/19 14:14:31 Looking through 39103309 seeds from seed 1566691200 generated at 2019-08-25 01:00:00 to seed 1605794509 generated at 2020-11-19 14:01:49 for 1 passwords of length 144 bits
2020/11/19 14:16:19 That took 1m47.826663577s for 362649.716710 seeds/s
2020/11/19 14:16:19 Looking through 39103309 seeds from seed 1566691200 generated at 2019-08-25 01:00:00 to seed 1605794509 generated at 2020-11-19 14:01:49 for 12 passwords of length 1024 bits
2020/11/19 14:18:10 That took 1m51.525192167s for 350623.103536 seeds/s


*** 3 Insecure passwords found
remote test-remote-1: "fJKeinHaUgkd_4pO0J70tUMUkvoxoPES5p7-"
remote test-remote-2: "r-zxEh10ufF9r48najyPn9UrmECuMhWTkIsEubDKtZ3fehFHMwY"
remote test-remote-3: "px0py_poF8Jzis0rxNGf2OvtVZPnmwUruqI1o3trhE1I8fcR3To"
```

**NB** don't make public any of the obscured passwords that rclone
prints - these can easily be reversed into the actual password. The
ones show here are for demonstration purposes.

