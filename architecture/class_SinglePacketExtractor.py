class SinglePacketExtractor:
    """Извлекает признаки из одного пакета"""

    def extract(self, packet):
        features = {}

        # 38. Tot size (размер пакета в байтах) - преобразуем в float
        features['Tot size'] = float(packet.length)

        # 1. Header_Length (длина IP заголовка в битах)
        if hasattr(packet, 'ip'):
            try:
                ihl = float(packet.ip.hdr_len)
                features['Header_Length'] = ihl * 4.0 * 8.0
            except (ValueError, AttributeError):
                features['Header_Length'] = 0.0
        else:
            features['Header_Length'] = 0.0

        # 2. Protocol Type (тип протокола: TCP/UDP/ICMP/OTHER)
        # Вместо строк используем числовые коды как в датасете
        if hasattr(packet, 'ip'):
            proto = packet.ip.proto
            if proto == '6':
                features['Protocol Type'] = 0.0  # TCP
            elif proto == '17':
                features['Protocol Type'] = 1.0  # UDP
            elif proto == '1':
                features['Protocol Type'] = 2.0  # ICMP
            else:
                # Для других протоколов используем уникальный код
                try:
                    features['Protocol Type'] = float(proto) + 10.0
                except (ValueError, TypeError):
                    features['Protocol Type'] = 99.0  # неизвестный
        else:
            features['Protocol Type'] = -1.0  # NO_IP

        # 3. Duration (TTL)
        if hasattr(packet, 'ip'):
            try:
                features['Duration'] = float(packet.ip.ttl)
            except (ValueError, AttributeError):
                features['Duration'] = 0.0
        else:
            features['Duration'] = 0.0

        # 26. TCP (бинарный) - float
        features['TCP'] = 1.0 if hasattr(packet, 'tcp') else 0.0

        # 27. UDP (бинарный) - float
        features['UDP'] = 1.0 if hasattr(packet, 'udp') else 0.0

        # 30. ICMP (бинарный) - float
        features['ICMP'] = 1.0 if hasattr(packet, 'icmp') else 0.0

        # 31. IPv (бинарный - есть IP заголовок или нет) - float
        features['IPv'] = 1.0 if hasattr(packet, 'ip') else 0.0

        # TCP флаги (для ОДНОГО пакета)
        # Инициализируем все флаги 0.0
        features['fin_flag_number'] = 0.0  # 7
        features['syn_flag_number'] = 0.0  # 8
        features['rst_flag_number'] = 0.0  # 9
        features['psh_flag_number'] = 0.0  # 10
        features['ack_flag_number'] = 0.0  # 11
        features['ece_flag_number'] = 0.0  # 12
        features['cwr_flag_number'] = 0.0  # 13

        # 17. urg_count (бинарный для одного пакета) - float
        features['urg_count'] = 0.0

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
            try:
                flags = int(packet.tcp.flags, 16)
                features['fin_flag_number'] = 1.0 if (flags & 0x001) else 0.0
                features['syn_flag_number'] = 1.0 if (flags & 0x002) else 0.0
                features['rst_flag_number'] = 1.0 if (flags & 0x004) else 0.0
                features['psh_flag_number'] = 1.0 if (flags & 0x008) else 0.0
                features['ack_flag_number'] = 1.0 if (flags & 0x010) else 0.0
                features['urg_count'] = 1.0 if (flags & 0x020) else 0.0
                features['ece_flag_number'] = 1.0 if (flags & 0x040) else 0.0
                features['cwr_flag_number'] = 1.0 if (flags & 0x080) else 0.0
            except (ValueError, AttributeError):
                pass  # оставляем нули

        # Порты (для определения сервисов)
        src_port = 0
        dst_port = 0

        try:
            if hasattr(packet, 'tcp'):
                src_port = int(packet.tcp.srcport)
                dst_port = int(packet.tcp.dstport)
            elif hasattr(packet, 'udp'):
                src_port = int(packet.udp.srcport)
                dst_port = int(packet.udp.dstport)
        except (ValueError, AttributeError):
            pass

        # Прикладные протоколы (по порту назначения) - float
        features['HTTP'] = 1.0 if dst_port in [80, 8080, 8000] else 0.0  # 19
        features['HTTPS'] = 1.0 if dst_port == 443 else 0.0  # 20
        features['DNS'] = 1.0 if dst_port == 53 else 0.0  # 21
        features['Telnet'] = 1.0 if dst_port == 23 else 0.0  # 22
        features['SMTP'] = 1.0 if dst_port in [25, 587] else 0.0  # 23
        features['SSH'] = 1.0 if dst_port == 22 else 0.0  # 24
        features['IRC'] = 1.0 if dst_port in [6667, 6668, 6669] else 0.0  # 25

        # 28. DHCP - float
        if hasattr(packet, 'udp'):
            try:
                src_port_udp = int(packet.udp.srcport)
                dst_port_udp = int(packet.udp.dstport)
                features['DHCP'] = 1.0 if src_port_udp in [67, 68] or dst_port_udp in [67, 68] else 0.0
            except (ValueError, AttributeError):
                features['DHCP'] = 0.0
        else:
            features['DHCP'] = 0.0

        # 29. ARP - float
        features['ARP'] = 1.0 if hasattr(packet, 'arp') else 0.0

        # 32. LLC - float
        features['LLC'] = 1.0 if hasattr(packet, 'llc') else 0.0

        # IP адреса (для группировки в flow - не являются признаками модели)
        if hasattr(packet, 'ip'):
            features['_src_ip'] = packet.ip.src  # с подчёркиванием = не для модели
            features['_dst_ip'] = packet.ip.dst
            features['_src_port'] = float(src_port)
            features['_dst_port'] = float(dst_port)
        elif hasattr(packet, 'arp'):
            features['_src_ip'] = getattr(packet.arp, 'src.proto_ipv4', '0.0.0.0')
            features['_dst_ip'] = getattr(packet.arp, 'dst.proto_ipv4', '0.0.0.0')
            features['_src_port'] = 0.0
            features['_dst_port'] = 0.0
        else:
            features['_src_ip'] = '0.0.0.0'
            features['_dst_ip'] = '0.0.0.0'
            features['_src_port'] = 0.0
            features['_dst_port'] = 0.0

        return features

