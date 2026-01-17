import numpy as np
import time
from class_SinglePacketExtractor import SinglePacketExtractor
from class_FlowStatistics import FlowStatistics


class NetworkFeatureExtractor:
    """Главный класс - объединяет всё"""

    def __init__(self):
        self.packet_extractor = SinglePacketExtractor()
        self.flows = {}  # flow_key -> FlowStatistics

    def _get_flow_key(self, packet_features):
        """Создаёт уникальный ключ для flow"""
        # Используем IP адреса и порты
        return (
            packet_features.get('_src_ip', '0.0.0.0'),
            packet_features.get('_dst_ip', '0.0.0.0'),
            float(packet_features.get('_src_port', 0.0)),
            float(packet_features.get('_dst_port', 0.0)),
            float(packet_features.get('Protocol Type', -1.0))
        )

    def process_packet(self, packet):
        """Обрабатывает один pyshark пакет"""
        # 1. Извлекаем признаки из пакета
        packet_features = self.packet_extractor.extract(packet)
        packet_features['_timestamp'] = float(time.time())  # временная метка как float

        # 2. Определяем flow
        flow_key = self._get_flow_key(packet_features)

        # 3. Добавляем в flow статистику
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowStatistics()

        self.flows[flow_key].add_packet(packet_features)

        # 4. Если накопилось достаточно пакетов, получаем статистику
        # (например, минимум 10 пакетов в flow)
        if len(self.flows[flow_key].packets) >= 10:
            flow_stats = self.flows[flow_key].get_statistical_features()

            if flow_stats:
                # 5. Объединяем все признаки
                all_features = {}

                # Сначала признаки из последнего пакета
                for key in packet_features:
                    if not key.startswith('_'):  # только признаки для модели
                        all_features[key] = float(packet_features[key])

                # Затем статистические признаки
                all_features.update(flow_stats)

                # 6. Возвращаем ВСЕ 46 признаков
                return all_features

        return None

    def get_all_features_list(self):
        """Возвращает список всех 46 признаков в правильном порядке"""
        return [
            'flow_duration', 'Header_Length', 'Protocol Type', 'Duration',
            'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
            'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
            'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count',
            'fin_count', 'urg_count', 'rst_count', 'HTTP', 'HTTPS', 'DNS',
            'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP', 'ARP',
            'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std',
            'Tot size', 'IAT', 'Number', 'Magnitue', 'Radius', 'Covariance',
            'Variance', 'Weight'
        ]

    def get_features_as_ordered_array(self, features_dict):
        """Преобразует словарь признаков в упорядоченный массив float"""
        ordered_features = []
        for feature_name in self.get_all_features_list():
            if feature_name in features_dict:
                ordered_features.append(float(features_dict[feature_name]))
            else:
                ordered_features.append(0.0)  # значение по умолчанию
        return np.array(ordered_features, dtype=float)
