# README.md

## Compile

### ONOS

- 총 두 가지의 app이 있음, 두 폴더 모두 providers에 넣고, 다음 코드를 수정해주세요
    1. **myapp, myndp 폴더**를 **providers 폴더**에 넣는다
    2. onos/tools/build/bazel의 modules.bzl의 provider_app_map 의 PROVIDER_APP_MAP 에 예
    전에 mymrspprovider추가했듯이 myndp와 myapp도 추가한다.
        
        ![Untitled](https://user-images.githubusercontent.com/54925185/172320937-b9174232-f82e-4fa4-9ab7-1087ceed396d.png)

        
    3. How to activate those apps? openflow, fwd 기능을 activate하듯이 activate한다.
        
         ![Untitled 1](https://user-images.githubusercontent.com/54925185/172321041-56fd81a1-f380-4d1f-80d3-aa6c37e72db1.png)


        

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
