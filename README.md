## Compile

### ONOS
---
### Mininet

1. terminal 창을 연다
2. sendDomain.c compile 한다.
    - `g++ test1 sendDomain.c`
3. custom 한 mininet topology file 실행
    - `$sudo python custom_topo.py`
4. mininet CLI 창에서 topology가 ping이 잘 되는지 확인
    - `$ mininet-wifi > pingall`
5. mininet CLI 창에서 `xterm` 창 open 하고 xterm 창에서 wireshark를 관리자 권한으로 실행한다.
    - `$ mininet-wifi > xterm sta1`
    - (in xterm) `$sudo wireshark`
6. mininet CLI 창에서 `xterm` 한 개 더 실행
    - `$ mininet-wifi > xterm sta1`
7. xterm 창에서 sendDomain.c 실행
    - `$ sudo ./test1 sta1-wan1`
