from dash import Dash, dcc, html, Input, Output, dash_table
import json
import pandas as pd
import plotly.express as px
import redis

# KeyValue config
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
ZSET_KEY = 'simulation:0'

# Signals config
RO_NAMES = []
NOF_RO = 0

app = Dash(__name__)

r = redis.Redis(host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                decode_responses=False)

def get_config():
    global RO_NAMES
    global NOF_RO
    RO_NAMES = []    
    with open('../simulator/config.json', 'r') as f:
        config = json.load(f)
        READ_TIMING_O =  config["READ_TIMING_O"]
        if READ_TIMING_O:
            for sign in READ_TIMING_O["SIGNALS"]:
                sign_name = sign["SIGN_NAME"]
                RO_NAMES.append(sign_name)
            NOF_RO = len(READ_TIMING_O["SIGNALS"])        

def get_df():
    global RO_NAMES
    global NOF_RO
    # get the current configuration
    get_config()
    # get the data from the cache
    raw_data = r.zrange(ZSET_KEY, 0, -1)
    if not raw_data:
        return pd.DataFrame()  # empty df
    
    parsed_rows = []
    max_signals = 0
    
    for item in raw_data:
        try:
            values = item.decode('utf-8').split(',')
            time = int(values[0])
            signals = [float(v) for v in values[1:]]
            max_signals = max(max_signals, len(signals))
            parsed_rows.append([time] + signals)
        except (ValueError, IndexError):
            continue # skip malformed rows
    
    if not parsed_rows:
        return pd.DataFrame()
    
    columns = ['time'] + [f'{RO_NAMES[i]}' for i in range(max_signals)]
    
    df = pd.DataFrame(parsed_rows, columns=columns)
    df.sort_values('time', inplace=True)  # redundant
    return df

app.layout = html.Div([
    html.H1("KeyValue dashboard"),
    dcc.Graph(id='live-graph'),
    html.Hr(),
    html.H3("Latest Data Table"),
    dash_table.DataTable(id='data-table', page_size=10),
    dcc.Interval(id='interval-component', interval=0.25*1000, n_intervals=0)
])

# callback for updating graph and table
@app.callback(
    [Output('live-graph', 'figure'), Output('data-table', 'data'), Output('data-table', 'columns')],
    Input('interval-component', 'n_intervals')
)
def update_dashboard(n):
    df = get_df()
    if df.empty:
        empty_fig = px.line(title="Waiting for data...")
        return empty_fig, [], []

    # dynamic plot: signal colums vs time
    signal_cols = [col for col in df.columns if col != "time"]
    fig = px.line(df, x='time', y=signal_cols,
                  title=f'Time series ({len(signal_cols)} signals detected)',
                  labels={'value': 'Signal Value', 'variable': 'Signals'})
    fig.update_layout(xaxis_title='Loop cycle')
    
    # table data
    table_data = df.to_dict('records')
    table_columns = [{"name": i, "id": i} for i in df.columns]
    
    return fig, table_data, table_columns

if __name__ == '__main__':
    app.run(debug=False,
            host='0.0.0.0',
            port=8050)
