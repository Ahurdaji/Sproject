from app import app, db
from app import Post, Category, Comment, User


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

    # Add a user (ensure this user exists or replace with an existing user ID)
    user = User.query.first()  # Get an existing user or create one if needed

    # Add a comment associated with the post and user
    comment = Comment(body="hey there", post_id=post1.id, user_id=user.id)
    db.session.add(comment)
    db.session.commit()
    print("Data inserted successfully!")