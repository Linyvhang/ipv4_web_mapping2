import ipaddress

def generate_ips_from_cidr(cidr: str,max_ips=None):
    network = ipaddress.IPv4Network(cidr, strict=False)
    count = 0
    for ip in network.hosts():
        # 排除私网地址
        if ip.is_private:
            continue
        yield str(ip)
        count+=1
        if max_ips and count >=max_ips:
            return
        print("ip_generator已完成")
if __name__ == "__main__":
    ip_iter = generate_ips_from_cidr("192.128.0.0/9")
    count = 0
    for ip in ip_iter:
        if count >= 256:
            break
        print(ip)
        count += 1
