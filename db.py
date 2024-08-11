from app import app, db
from app import Post, Category, Comment


with app.app_context():
    # Create the tables
    db.create_all()
    print("Tables created successfully!")

    # Add a new category
    py = Category(name='Python')
    db.session.add(py)
    db.session.commit()  # Commit to save the category to the database

    # Add a post with the new category
    post1 = Post(title="My first post", subtitle="Ain't ya proud?", body="[content goes here]", category=py)
    db.session.add(post1)
    db.session.commit()  # Commit to save the post to the database

    comment = Comment(body="hey there")
    db.session.add(comment)
    db.session.commit()

    print("Data inserted successfully!")