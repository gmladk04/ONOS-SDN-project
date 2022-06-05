# ONOS-SDN-project
## Compile 방법

### ONOS

---

### Mininet

1. terminal 창을 열고 `sendDomain.c` 를 compile 한다.
    - `g++ test1 sendDomain.c`
    
2. terminal 창을 열고 mininet topology 를 실행하여 `mininet-wifi`를 실행한다.
    - `$ sudo python custom_topo.py`
    
3. `mininet-wifi` CLI 에서 서로 연결이 잘 됐는지 확인한다.
    - `mininet-wifi > pingall`
    
4. `mininet-wifi` 에서 `ping` 이 잘 가는지 확인한다.
    - `mininet-wifi > sta1 ping h1`
    
5. `mininet-wifi` 에서 `sta1` 에 대해 `xterm` 을 실행한다.
    - `mininet-wifi > xterm sta1`
    
6. `xterm` 창에서 **관리자 권한**으로 wireshark를 실행한다.
    - `sudo wireshark`
    
7. `mininet-wifi` CLI 로 돌아가서 `xterm` 을 하나 더 띄운다.
    - `mininet-wifi > xterm sta1`
    
8. `sendDomain` 을 compile 한다.
    - `$sudo ./test1 sta1-wan1`
    
9. 결과창 확인
