from flask import Flask, render_template, request
# object ho and app ko thau ma aru ni lagna milxa
app=Flask(__name__)

@app.route('/menu')
def menu():
     return render_template('menu.html')

@app.route('/about')
def about():
     return render_template('about.html')

@app.route('/category')
def category():
     return render_template('category.html')

@app.route('/order')
def order():
     return render_template('order.html')
if __name__ =='__main__':
    app.run(debug=True)