import nmap


def hosts_inventory(network):
    nm = nmap.PortScanner()
    nm_list = nm.scan(hosts=network, arguments='-sS -O')
    if not nm_list['scan']:
        print('\n!!!Invalid ip_address or domain_name!!!\n')
        return

    types_list = []
    hosts_list = []
    for host in nm.all_hosts():
        try:
            host_type = nm[host].all_ip.im_self[
                'osmatch'][0]['osclass'][0]['type']
            types_list.append(host_type)
            host_params = {}
            host_params['host_type'] = host_type
            host_params['os'] = nm[host].all_ip.im_self[
                'osmatch'][0]['osclass'][0]['vendor']
            host_params['hostname'] = nm[
                host].all_ip.im_self['hostnames'][0]['name']
            host_params['ipv4'] = nm[host].all_ip.im_self['addresses']['ipv4']
            hosts_list.append(host_params)
        except IndexError:
            pass

    availables_types = list(set(host_type for host_type in types_list))

    type_groups = []
    for host_type in availables_types:
        type_groups.append([host for host in hosts_list
                            if host['host_type'] == host_type])

    for host in hosts_list:
        availables_os = list(set(host['os'] for host in hosts_list))

    with open('inventory_report.txt', 'w') as report:
        report.write('Network: %s\n\n' % network)
        for group in type_groups:
            print('\n\nDevive type: %s\n' % (group[0]['host_type']))
            report.write('Devive type - %s:\n' % (group[0]['host_type']))
            count = 0
            for host in group:
                count += 1
                print('%s. ip_address = %s, hostname = %s, OS = %s' %
                      (count, host['ipv4'],
                       host['hostname'], host['os']))
                report.write('%s. ip_address = %s, hostname = %s, OS = %s\n' %
                             (count, host['ipv4'],
                              host['hostname'], host['os']))
            report.write('\n\n')
    print('\n')


if __name__ == '__main__':
    start = raw_input('\nHello, Press any key for start...\n')
    network = raw_input('Enter the network to scan (format: x.x.x.x/mask): ')
    print('\nStarting hosts inventory. Network: %s\nPlease wait...' % network)
    hosts_inventory(network)
