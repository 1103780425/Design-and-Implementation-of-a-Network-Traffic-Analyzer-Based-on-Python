from dash import Dash, dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import numpy as np

app = Dash(__name__)

def get_network_data():
    return np.random.rand(10)

app.layout = html.Div([
    dcc.Graph(id='live-update-graph'),
    dcc.Interval(
        id='interval-component',
        interval=1*1000,  # 每秒更新一次
        n_intervals=0
    )
])

@app.callback(Output('live-update-graph', 'figure'),
              Input('interval-component', 'n_intervals'))
def update_graph_live(n):
    data = get_network_data()
    graph = go.Scatter(
        x=list(range(len(data))),
        y=data,
        mode='lines+markers'
    )

    return {'data': [graph], 'layout': go.Layout(title='Network Traffic')}

if __name__ == '__main__':
    app.run_server(debug=True)
