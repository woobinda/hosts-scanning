import nmap


def port_scan(host, filename='scan_report.txt'):
    nm = nmap.PortScanner()
    nm_list = nm.scan(host, '1-5000')
    if not nm_list['scan']:
        print('\n!!!Invalid ip_address or domain_name!!!\n')
        return

    with open(filename, 'w') as report:
        for host in nm.all_hosts():
            print('\n' + '-' * 40)
            print('Host: %s (%s)' % (host, nm[host].hostname()))
            report.write('Host: %s (%s)\n\n' % (host, nm[host].hostname()))

            for proto in nm[host].all_protocols():
                print('-' * 30 + '\n')
                print('Protocol: %s' % proto)
                report.write('Protocol: %s\n\n' % proto)
                ports_list = nm[host][proto].keys()
                ports_list.sort()

                for port in ports_list:
                    print ('port : %s\tstate : %s\tproduct : %s' %
                           (port, nm[host][proto][port]['state'],
                            nm[host][proto][port]['product']))
                    report.write('port : %s\tstate : %s\tproduct : %s\n' %
                                 (port, nm[host][proto][port]['state'],
                                  nm[host][proto][port]['product']))
    print('\n')


if __name__ == '__main__':
    start = raw_input('\nHello, Press any key for start...\n')
    host = raw_input('Enter the ip_address or domain_name to scan: ')
    print('\nStarting port scanning. Host: %s\nPlease wait...' % host)
    port_scan(host)
