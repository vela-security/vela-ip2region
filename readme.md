# ip2region
>  获取IP地址的地理位置库 注意: 需要发布三方组件

## 内置方法
- [vela.ip2region(cfg)](#ip2region) &emsp;获取ip2region地址信息
- [vela.region(ip)](#查看) &emsp;查询IP地址信息
- [vela.with_ip2region([ip2region](#ip2region))](#设置全局) &emsp;设置为全局IP地址信息


## ip2region
> region = vela.ip2region(cfg)  生成一个IPv4地址查询库 <br />

cfg配置信息:
- name &emsp;对象名称
- xdb &emsp;库位置
- method &emsp;查询方式分别: file , index ,memory

```lua

    local r = vela.ip2region{
        name = "search",
        xdb  = "share/ip2region/ip2region.xdb",
        method = "index",
    }

    start(r)

    vela.with_ip2region(r)
```

## 查看
> 如果设置了全局 可以利用 vela.region(ip) 或者 利用region对象查询
```lua
    local r = vela.ip2region {
        name = "search",
        xdb  = "share/ip2region/ip2region.xdb",
        method = "index",
    } 
    start(r) 
    print(r.region("114.114.114.114"))

    vela.with_ip2region(r)
    vela.region("114.114.114.114")
```

## 设置全局
> vela.with_ip2region(v) &emsp;v:为全局的region对象 <br />
> 设置为全局后 程序中可以直接内部利用xEnv.region(ip)获取信息

```lua
    vela.with_ip2region(r)
    vela.region("114.114.114.114")
```