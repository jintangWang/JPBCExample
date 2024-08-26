### F_AuthenticationContract 智能合约部署过程
- 通过 gradle 命令打包该智能合约代码： `./gradlew installDist`
- 将打包出来的build文件夹放到 `/path to fabric-samples/fabric-samples/chaincode/authentication-contract/java/` 下
- 然后通过启动 fabric test-network 进行调试
```shell 
# 进入 test-network 目录
cd /path to fabric-samples/fabric-samples/test-network/
# 启动 docker 之后启动 fabric 测试网络 
./network.sh up createChannel -ca
# 部署智能合约
./network.sh deployCC -ccn authcc -ccp ../chaincode/authentication-contract/java -ccl java
# 调用智能合约

```