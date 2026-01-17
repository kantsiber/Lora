import time
import numpy as np


class FlowStatistics:
    """Считает статистические признаки для flow с ТОЧНЫМИ названиями"""

    def __init__(self):
        self.packets = []  # список признаков пакетов в flow
        self.start_time = None

        # Счётчики для статистических признаков
        self._ack_count = 0.0  # 14
        self._syn_count = 0.0  # 15
        self._fin_count = 0.0  # 16
        self._rst_count = 0.0  # 18

        # Для статистик по размерам
        self._packet_sizes = []
        self._timestamps = []

    def add_packet(self, packet_features):
        """Добавляет пакет в flow"""
        # Сохраняем пакет
        self.packets.append(packet_features)

        # Время начала flow
        if self.start_time is None:
            self.start_time = packet_features.get('_timestamp', time.time())

        # Обновляем счётчики флагов
        self._ack_count += float(packet_features.get('ack_flag_number', 0.0))
        self._syn_count += float(packet_features.get('syn_flag_number', 0.0))
        self._fin_count += float(packet_features.get('fin_flag_number', 0.0))
        self._rst_count += float(packet_features.get('rst_flag_number', 0.0))

        # Сохраняем размеры и временные метки
        self._packet_sizes.append(float(packet_features.get('Tot size', 0.0)))
        self._timestamps.append(float(packet_features.get('_timestamp', time.time())))

    def get_statistical_features(self):
        """Возвращает статистические признаки flow"""
        if len(self.packets) < 2:
            return None

        stats = {}

        # 0. flow_duration (в секундах) - float
        end_time = float(self._timestamps[-1])
        stats['flow_duration'] = end_time - float(self.start_time)

        # 4. Rate (пакетов в секунду) - float
        if stats['flow_duration'] > 0:
            stats['Rate'] = float(len(self.packets)) / stats['flow_duration']
        else:
            stats['Rate'] = 0.0

        # 5. Srate, 6. Drate (пока одинаковые) - float
        stats['Srate'] = float(stats['Rate'])
        stats['Drate'] = float(stats['Rate'])

        # 14-18. Счётчики флагов - float
        stats['ack_count'] = float(self._ack_count)
        stats['syn_count'] = float(self._syn_count)
        stats['fin_count'] = float(self._fin_count)
        stats['rst_count'] = float(self._rst_count)

        # urg_count уже есть в каждом пакете (17)
        # Берём из последнего пакета или можно посчитать среднее

        # 33. Tot sum (сумма размеров всех пакетов) - float
        stats['Tot sum'] = float(np.sum(self._packet_sizes))

        # 34-37. Статистики по размерам - все float
        stats['Min'] = float(np.min(self._packet_sizes)) if self._packet_sizes else 0.0
        stats['Max'] = float(np.max(self._packet_sizes)) if self._packet_sizes else 0.0
        stats['AVG'] = float(np.mean(self._packet_sizes)) if self._packet_sizes else 0.0

        if len(self._packet_sizes) > 1:
            stats['Std'] = float(np.std(self._packet_sizes, ddof=1))
        else:
            stats['Std'] = 0.0

        # 40. Number (количество пакетов в flow) - float
        stats['Number'] = float(len(self.packets))

        # 39. IAT (Inter-Arrival Time) - float
        if len(self._timestamps) > 1:
            try:
                iats = np.diff(np.array(self._timestamps, dtype=float))
                if len(iats) > 0:
                    stats['IAT'] = float(np.mean(iats))
                else:
                    stats['IAT'] = 0.0
            except Exception:
                stats['IAT'] = 0.0
        else:
            stats['IAT'] = 0.0

        # 41-45. Дополнительные статистики (простые формулы)
        # 41. Magnitue - float
        try:
            stats['Magnitue'] = float(np.sqrt(stats['Tot sum'] ** 2 + stats['Number'] ** 2))
        except Exception:
            stats['Magnitue'] = 0.0

        # 42. Radius - float
        try:
            stats['Radius'] = float(np.sqrt(stats['AVG'] ** 2 + stats['Std'] ** 2))
        except Exception:
            stats['Radius'] = 0.0

        # 45. Variance - float
        if len(self._packet_sizes) > 1:
            stats['Variance'] = float(np.var(self._packet_sizes, ddof=1))
        else:
            stats['Variance'] = 0.0

        # 46. Weight - float
        try:
            stats['Weight'] = float(stats['Tot sum'] / 1000.0)
        except Exception:
            stats['Weight'] = 0.0

        # 44. Covariance (ковариация размеров и интервалов) - float
        if len(self._packet_sizes) > 1 and len(self._timestamps) > 1:
            try:
                # Подготовка данных для ковариации
                sizes_for_cov = self._packet_sizes[:-1]  # все кроме последнего
                iats_for_cov = np.diff(np.array(self._timestamps, dtype=float))

                min_len = min(len(sizes_for_cov), len(iats_for_cov))
                if min_len > 1:
                    sizes_for_cov = sizes_for_cov[:min_len]
                    iats_for_cov = iats_for_cov[:min_len]

                    cov_matrix = np.cov(sizes_for_cov, iats_for_cov)
                    if cov_matrix.shape == (2, 2):
                        stats['Covariance'] = float(cov_matrix[0, 1])
                    else:
                        stats['Covariance'] = 0.0
                else:
                    stats['Covariance'] = 0.0
            except Exception as e:
                stats['Covariance'] = 0.0
        else:
            stats['Covariance'] = 0.0

        return stats

