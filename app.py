from flask import Flask, render_template, request
from flask_bootstrap import Bootstrap

app = Flask(__name__)
bootstrap = Bootstrap(app)

# Import all your functions here
from crawler import *

app = Flask(__name__)
Bootstrap(app)

@app.route('/', methods=['GET', 'POST'])
def home():
    url = ''
    if request.method == 'POST':
        url = request.form['url']
        # Do something with the url using your functions
        try:
            indicators = crawl(url, set())
            write_indicators(indicators, output_file="indicators2.csv")
            indicators_df = pd.read_csv("indicators2.csv")  # read the csv file
            return render_template('success.html', url=url, table=indicators_df.to_html(index=False))  # convert dataframe to html table
 
        except Exception as e:
            return render_template('error.html', error=e)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)