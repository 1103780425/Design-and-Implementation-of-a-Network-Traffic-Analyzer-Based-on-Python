import pandas as pd
import sqlite3

def load_protocol_usage():
    conn = sqlite3.connect('network_data.db')
    query = "SELECT * FROM ProtocolUsage"
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def load_ip_stats():
    conn = sqlite3.connect('network_data.db')
    query = "SELECT * FROM IPStats"
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def load_tcp_flags():
    conn = sqlite3.connect('network_data.db')
    query = "SELECT * FROM TCPFlags"
    df = pd.read_sql_query(query, conn)
    conn.close()
    # print("Loaded TCP flags:", df.head())  # 打印前几行数据以检查
    return df

def load_layer_sequence():
    conn = sqlite3.connect('network_data.db')
    query = "SELECT * FROM LayerSequence"
    df = pd.read_sql_query(query, conn)
    # print(df.head())  # 打印加载的数据看是否正确
    conn.close()
    return df

def analyze_protocol_usage(df):
    # 这里添加特定的分析代码
    # return df['protocol'].value_counts()
    result = df.groupby('protocol')['count'].sum()
    return result

def analyze_ip_stats(df):
    # src_ip_counts = df[df['type'] == 'source']['ip_address'].value_counts()
    # dst_ip_counts = df[df['type'] == 'destination']['ip_address'].value_counts()
    # return src_ip_counts, dst_ip_counts
    # 修改此函数以处理count字段
    src_df = df[df['type'] == 'source']
    dst_df = df[df['type'] == 'destination']
    src_ip_counts = src_df.groupby('ip_address')['count'].sum()
    dst_ip_counts = dst_df.groupby('ip_address')['count'].sum()
    return src_ip_counts, dst_ip_counts

def analyze_tcp_flags(df):
    # 直接将 'flag' 作为键，'count' 作为值创建字典
    results = dict(zip(df['flag'], df['count']))
    print("Analyzed TCP flags:", results)  # 打印分析结果
    return results
    # return df['flag'].value_counts()

def analyze_layer_sequence(df):
    result = df.groupby('sequence').sum()  
    print(result)  # 打印分析结果
    return result
    # return df['sequence'].value_counts()

def format_analysis_results(title, results):
    """
    格式化分析结果为更易读的字符串。
    """
    formatted_results = f"分析结果 - {title}：\n"
    if isinstance(results, pd.Series):
        for key, value in results.items():
            formatted_results += f"{key} 出现了 {value} 次\n"
    elif isinstance(results, dict):
        for key, value in results.items():
            formatted_results += f"{key} 出现了 {value} 次\n"
    else:
        formatted_results += "无有效数据\n"
    return formatted_results
    # formatted_results = f"分析结果 - {title}：\n"
    # for key, value in results.items():
    #     formatted_results += f"{key} 出现了 {value} 次\n"
    # print(formatted_results)  # 打印格式化后的结果
    # return formatted_results


# 示例用法
# protocol_df = load_protocol_usage()
# protocol_analysis = analyze_protocol_usage(protocol_df)

# ip_stats_df = load_ip_stats()
# src_ip_counts, dst_ip_counts = analyze_ip_stats(ip_stats_df)

# tcp_flags_df = load_tcp_flags()
# tcp_flags_analysis = analyze_tcp_flags(tcp_flags_df)

# layer_sequence_df = load_layer_sequence()
# layer_sequence_analysis = analyze_layer_sequence(layer_sequence_df)


# Example usage
# df = load_data_from_db()
# cleaned_data = clean_and_analyze(df)
# print(cleaned_data)
