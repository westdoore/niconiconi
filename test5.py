import asyncio

import checker


async def test_check_list():
    ips = ['https://46.3.105.217:10049', 'http://www.kerangwincare.art', 'https://www.kerangwincare.art',
           'http://kerangwincare.art', 'https://kerangwincare.art', 'https://www.kerangwinfest.vip',
           'http://www.kerangwinfest.vip', 'https://kerangwinfest.vip', 'http://kerangwinfest.vip',
           'https://61.93.47.11:50000', 'https://103.229.54.151:9527', 'https://203.184.131.22:20000',
           'https://46.3.105.217:10043', 'https://46.3.105.217:10040', 'https://46.3.105.217:10036',
           'https://47.76.62.62:8443', 'https://46.3.105.217:10034', 'https://46.3.105.217:10033',
           'https://47.76.252.161:10002', 'https://149.104.24.14:2096', 'https://203.184.131.22:20000',
           'https://46.3.105.217:10043', 'https://46.3.105.217:10040', 'https://46.3.105.217:10036',
           'https://47.76.62.62:8443', 'https://46.3.105.217:10034', 'https://46.3.105.217:10033',
           'https://47.76.252.161:10002', 'https://149.104.24.14:2096', 'https://149.104.29.178',
           'https://47.76.94.15:8443', 'https://210.0.158.18:20000', 'https://46.3.105.217:10029',
           'https://46.3.106.170:10029', 'https://46.3.105.217:10028', 'https://46.3.106.170:10028',
           'https://8.217.49.34:2087', 'https://8.218.3.12:2087', 'https://47.76.37.57:2096',
           'https://46.3.106.170:10027']

    for i in ips:
        ip_str = i.split("//")[1]
        ip = None
        port = None
        if ":" in ip_str:
            ip = ip_str.split(":")[0]
            port = ip_str.split(":")[1]
        else:
            ip = ip_str
            port = '443'
        cloudflare_proxy = await checker.check_if_cf_proxy(ip, port)
        print(f"ip: {ip},port:{port}, cf-proxy:{cloudflare_proxy}")
        await asyncio.sleep(1)


async def test_check_one():
    c2 = await checker.check_if_cf_proxy('34.80.252.27', 443)
    print(f"cloudflare_proxy: {c2}")


async def test_check_ones():
    a = [('43.134.1.188', 8443), ('150.109.24.233', 6666), ('43.156.37.138', 55555), ('43.128.98.24', 443),
         ('43.134.57.24', 8443), ('43.133.35.90', 8443), ('43.156.156.226', 9001), ('43.134.17.191', 8820),
         ('jagotebakangka.com', 443), ('43.134.3.185', 443), ('43.134.95.38', 443), ('43.156.55.171', 443),
         ('43.134.44.29', 443), ('www.jagotebakangka.com', 443), ('150.109.9.197', 443), ('43.156.76.102', 8686),
         ('129.226.92.20', 443), ('43.156.119.123', 58000), ('101.32.242.254', 8080), ('43.134.172.3', 443),
         ('43.153.224.111', 1955), ('43.156.117.152', 443), ('43.134.187.193', 8989), ('43.134.228.51', 2053),
         ('43.156.9.186', 443), ('43.134.18.126', 443), ('43.156.175.106', 443), ('www.jagotebakangka.com', 443),
         ('43.156.5.31', 443), ('43.134.177.75', 8806), ('43.134.82.225', 443), ('43.134.18.117', 2083),
         ('129.226.158.125', 8088), ('43.134.129.162', 443), ('43.152.72.166', 443), ('43.134.169.46', 6688),
         ('43.134.66.62', 8814), ('129.226.202.174', 8822), ('43.134.32.117', 8807), ('43.156.10.94', 443),
         ('43.156.69.80', 443), ('43.128.81.216', 443), ('43.134.2.191', 443), ('43.156.34.207', 443),
         ('43.153.210.88', 443), ('129.226.151.131', 8817), ('43.134.87.70', 8443), ('43.134.179.91', 443),
         ('43.156.40.146', 443), ('jagotebakangka.com', 443), ('43.134.178.18', 8443), ('43.134.186.58', 443),
         ('43.134.18.117', 2087), ('129.226.217.222', 8819), ('43.156.243.49', 20040), ('129.226.146.188', 443),
         ('43.156.29.194', 8817)]
    for i in a:
        cf_proxy_i_i_ = await checker.check_if_cf_proxy(i[0], i[1])
        print(cf_proxy_i_i_)


async def main():
    # await test_check_list()
    await test_check_one()
    # await test_check_ones()

if __name__ == '__main__':
    asyncio.run(main())
    # a = ('abc',12)
    # b = ('abc',12)
    # aa = set()
    # aa.add(a)
    # aa.add(b)
    # if a in aa:
    #     print(f"cloud")
    # print(len(aa))
