from app import app, db
from app import Post, Category

py = Category(name='Python')
post1= Post(title="My first post" , subtitle="Ain`t ya proud?", body="[content goes here]", category=py )
db.session.add(post1)
db.session.commit()

with app.app_context():
    db.create_all()
    print("Tables created success")

db.create_all()