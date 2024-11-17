import os
import socket
from flask import Flask, current_app, request, jsonify,send_file, Response
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
import fitz
from flask_cors import CORS
from flask_pymongo import PyMongo
from flask_bcrypt import check_password_hash
import secrets
from flask_bcrypt import Bcrypt
from bson import json_util
from gridfs import GridFS
import pymongo
from mongoengine import connect, Document, StringField
from io import BytesIO
import uuid
from bson import ObjectId
import openai
import json
import requests
import openai
import pandas as pd
from datetime import datetime

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
app.config["MONGO_URI"] = (
    "mongodb+srv://shripad:root@cluster0.c8sam.mongodb.net/mydatabase?retryWrites=true&w=majority"
)
mongo = PyMongo(app)

bcrypt = Bcrypt(app)

app.config["JWT_SECRET_KEY"] = secrets.token_urlsafe(32)
jwt = JWTManager(app)


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()

    user = mongo.db.student.find_one(
        {"$or": [{"seatNumber": data.get("username")}, {"email": data.get("username")}]}
    )
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    mac_address = ":".join(
            [
                "{:02x}".format((uuid.getnode() >> elements) & 0xFF)
                for elements in range(0, 2 * 6, 2)
            ][::-1]
        )

    user_data = pd.DataFrame({'Host Name': [hostname], 'IP Address':ip_address,'Mac Address':mac_address,'Timestamp': [datetime.now()]})

    excel_file_path = 'user_info.xlsx'
    if os.path.exists(excel_file_path):
        existing_data = pd.read_excel(excel_file_path)
        user_data = pd.concat([existing_data, user_data], ignore_index=True)

    user_data.to_excel(excel_file_path, index=False)

    print("User information recorded successfully!")

    if user and check_password_hash(user["password"], data.get("password")):
        payload = {
            "firstName": user["firstName"],
            "lastName": user["lastName"],
            "rollNumber": user["rollNumber"],
            "seatNumber": user["seatNumber"],
            "year": user["year"],
            "email": user["email"],
        }
        
        access_token = create_access_token(identity=payload)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/adminlogin", methods=["POST"])
def teacherlogin():
    data = request.get_json()
    
    # Validate if the user exists in the database and match password
    user = mongo.db.admin.find_one({"email": data.get("email")})
    
    if user and bcrypt.check_password_hash(user["password"], data.get("password")):
        if user["role"] == "admin":
            payload = {
                "Name": user["firstName"] + " " + user["lastName"],
                "email": user["email"],
                "role": user["role"],
            }
            # Create an access token for admin
            access_token = create_access_token(identity=payload)
            return jsonify(access_token=access_token), 200
        else:
            return jsonify({"error": "Not authorized. Admin login required"}), 403
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


@app.route("/api/profile", methods=["GET"])
@jwt_required()
def get_profile():
    current_user = get_jwt_identity()
    user_id = current_user.get("seatNumber")

    # Fetch user details from the database
    user = mongo.db.student.find_one({"seatNumber": user_id}, {"_id": 0, "password": 0})

    if user:
        return jsonify(user), 200
    else:
        return jsonify({"error": "User not found"}), 404


@app.route("/api/profile/update", methods=["PUT"])
@jwt_required()
def update_profile():
    current_user = get_jwt_identity()
    user_email = current_user["email"]
    data = request.get_json()

    if "password" in data:
        data["password"] = bcrypt.generate_password_hash(data["password"]).decode(
            "utf-8"
        )

    result = mongo.db.student.update_one({"email": user_email}, {"$set": data})

    if result.modified_count > 0:
        return jsonify({"message": "Profile updated successfully"}), 200
    else:
        return jsonify({"error": "Failed to update profile"}), 500


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    print(data)
    # Check if the user already exists in the database
    try:
        existing_user = mongo.db.users.find_one({"email": data["email"]})
        if existing_user:
            return jsonify({"error": "User with this email already exists"}), 400
    except:
        print("Exception")
    # Hash the password before storing it
    hashed_password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")

    # Store the user data in the database
    new_user = {
        "firstName": data["firstName"],
        "lastName": data["lastName"],
        "rollNumber": data["rollNumber"],
        "seatNumber": data["seatNumber"],
        "year": data["year"],
        "email": data["email"],
        "password": hashed_password,
    }

    mongo.db.student.insert_one(new_user)

    return jsonify({"message": "User successfully registered"}), 201

@app.route("/api/admin/signup", methods=["POST"])
def signupAdmin():
    data = request.get_json()
    print(data)
    # Check if the user already exists in the database
    try:
        existing_user = mongo.db.admin.find_one({"email": data["email"]})
        if existing_user:
            return jsonify({"error": "User with this email already exists"}), 400
    except:
        print("Exception")
    # Hash the password before storing it
    hashed_password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    

    role = "admin" if data.get("isAdmin") else "user"  # Check if `isAdmin` is in the payload

    # Store the user data in the database
    new_admin = {
        "firstName": data["firstName"],
        "lastName": data["lastName"],
        "email": data["email"],
        "password": hashed_password,
        "role":role
    }

    mongo.db.admin.insert_one(new_admin)

    return jsonify({"message": "admin successfully registered"}), 201


@app.route("/api/QuestionPaperInsertion", methods=["POST"])
def receive_data_from_frontend():
    # Get the data sent from the frontend
    data_from_frontend = request.json

    # Process the data if needed (e.g., validate, transform)
    processed_data = data_from_frontend

    # Insert the processed data into the MongoDB database
    mongo.db.TeacherQuestionPaper.insert_one(processed_data)

    # Return a response to the frontend
    response = {"message": "Data received and stored in the database successfully"}
    return jsonify(response)


@app.route("/api/data/papers", methods=["POST"])
def receive_paper_data_from_frontend():
    data_from_frontend = request.json

    existing_user = mongo.db.papers.find_one(
        {
            "firstName": data_from_frontend["firstName"],
            "lastName": data_from_frontend["lastName"],
            "email": data_from_frontend["email"],
            "seatNumber": data_from_frontend["seatNumber"],
            "year": data_from_frontend["year"],
            "paperId": data_from_frontend["paperId"],
        }
    )

    if existing_user:
        return jsonify({"error": "User with this email already exists"}), 400

    processed_data = data_from_frontend

    # Insert the processed data into the MongoDB "papers" collection
    mongo.db.papers.insert_one(processed_data)

    # Return a response to the frontend
    response = {
        "message": "Paper data received and stored in the 'papers' collection successfully"
    }
    return jsonify(response)


@app.route("/api/data/papers/submission-status", methods=["POST"])
def check_submission_status():
    try:
        data_from_frontend = request.json
        existing_user = mongo.db.papers.find_one(
            {
                "email": data_from_frontend["email"],
                "seatNumber": data_from_frontend["seatNumber"],
                "paperId": data_from_frontend["paperId"]["$oid"],
                "rollNumber": data_from_frontend["rollNumber"],
            }
        )

        if existing_user:
            return jsonify({"submitted": False}), 200
        else:
            return jsonify({"submitted": True}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/api/data/papers/evaluation-status", methods=["POST"])
def check_evaluation_status():
    try:
        data_from_frontend = request.json
        existing_user = mongo.db.evaluated.find_one(
            {
                "email": data_from_frontend["email"],
                "seatNumber": data_from_frontend["seatNumber"],
                "paperId": data_from_frontend["paperId"],
                "rollNumber": data_from_frontend["rollNumber"],
            }
        )
        if existing_user:
            return jsonify({"submitted": False}), 200
        else:
            return jsonify({"submitted": True}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500
    
@app.route("/api/view-submission/<string:paper_id>", methods=["GET"])
def get_test_submission_details(paper_id):
    try:
        paper_object_id = ObjectId(paper_id)
        student_list = list(mongo.db.papers.find({"paperId": paper_id}))
        for student in student_list:
            student["_id"] = str(student["_id"])
        return jsonify(student_list), 200

    except Exception as e:
        return jsonify({"error": "An error occurred while processing the request"}), 500

def init_gridfs():
    with current_app.app_context():
        fs = GridFS(mongo.db)
        # fs = GridFS(mongo.db, collection="papers")
    return fs


class PdfDetails(Document):
    title = StringField()


@app.route("/upload-files", methods=["POST"])
def upload_files():
    try:
        title = request.form.get("title")
        file = request.files["file"]
        firstName = request.form.get("firstName")
        lastName = request.form.get("lastName")
        rollNumber = request.form.get("rollNumber")
        seatNumber = request.form.get("seatNumber")
        year = request.form.get("year")
        email = request.form.get("email")
        paperId = request.form.get("paperId")

        if file:
            # Generate a unique filename using uuid
            filename = str(uuid.uuid4()) + "_" + file.filename
            # Initialize GridFS within the application context
            fs = init_gridfs()

            # Open the file and store its contents in GridFS
            file_content = BytesIO(file.read())
            fs.put(
                file_content,
                filename=filename,
                title=title,
                contentType="application/pdf",
                firstName=firstName,
                lastName=lastName,
                rollNumber=rollNumber,
                seatNumber=seatNumber,
                year=year,
                email=email,
                paperId = paperId
            )
            print(firstName)

            return jsonify({"status": "ok"}), 200

        else:
            return jsonify({"status": "error", "message": "No file provided"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/data/teacher/papers", methods=["GET"])
def get_paper_data_TeacherQuestionPaper():
    papers_data = list(mongo.db.TeacherQuestionPaper.find({}))

    if papers_data:
        papers_data = json_util.dumps(papers_data)
        return papers_data, 200
    else:
        return jsonify({"error": "No papers data found"}), 404

@app.route('/api/student-answer-papers/<string:paper_id>/<string:seat_number>', methods=['GET'])
def get_students_answer_paper_details(paper_id,seat_number):
    try:
        paper_object_id = paper_id
        seatNumber = seat_number
        question_paper = mongo.db.papers.find_one({'paperId': paper_object_id, 'seatNumber': seatNumber})
        if not question_paper:
            return jsonify({'error': 'Question paper not found'}), 404
        question_paper['_id'] = str(question_paper['_id'])  
        return jsonify(question_paper)
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500
    
@app.route("/api/papers/<string:paper_id>", methods=["GET"])
def get_paper_details(paper_id):
    try:

        # Convert paper_id to ObjectId
        paper_object_id = ObjectId(paper_id)

        # Fetch the question paper details from MongoDB based on paper_id
        question_paper = mongo.db.TeacherQuestionPaper.find_one(
            {"_id": paper_object_id}
        )

        if not question_paper:
            return jsonify({"error": "Question paper not found"}), 404

        question_paper["_id"] = str(question_paper["_id"])
        return jsonify(question_paper)

    except Exception as e:

        return jsonify({"error": "Internal server error"}), 500


@app.route("/api/check-paper-existence/<string:paper_id>", methods=["GET"])
def check_paper_existence(paper_id):
    try:
        paper_object_id = paper_id
        paper_exists = mongo.db.TeacherModelAnswerPaper.find_one(
            {"paperId": paper_object_id}
        )

        if paper_exists is not None:
            return jsonify({"exists": True}), 200
        else:
            return (
                jsonify({"exists": False}),
                404,
            )  # Assuming 404 is appropriate for paper not found

    except Exception as e:
        return jsonify({"error": "An error occurred while processing the request"}), 500
    
@app.route("/api/assignments/<string:paper_id>/accept", methods=["POST"])

def accept_assignment(paper_id):
    try:
      
        # Ensure the current user is an admin
        # Get the user_id from the request body
   
        # Find the assignment by its ID
        assignment = mongo.db.papers.find_one({"_id": ObjectId(paper_id)})
        if not assignment:
            return jsonify({"error": "Assignment not found"}), 404

        # Check if the assignment belongs to the user
        # Update the assignment status to accepted
        result = mongo.db.papers.update_one(
            {"_id": ObjectId(paper_id)},
            {"$set": {"status": "accepted"}}
        )

        if result.modified_count > 0:
            return jsonify({"message": "Assignment accepted successfully"}), 200
        else:
            return jsonify({"error": "Failed to accept assignment"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/assignments/<string:paper_id>/reject", methods=["POST"])
  # Ensure that the admin is authenticated
def reject_assignment(paper_id):
    try:
        # Fetch the current user from the JWT
        # Find the assignment by its ID
        assignment = mongo.db.papers.find_one({"_id": ObjectId(paper_id)})
        print(f"Assignment found: {assignment}")  # Log the assignment

        if not assignment:
            return jsonify({"error": "Assignment not found"}), 404

        # Update the assignment status to rejected
        result = mongo.db.papers.update_one(
            {"_id": ObjectId(paper_id)},
            {"$set": {"status": "rejected"}}
        )

        if result.modified_count > 0:
            return jsonify({"message": "Assignment rejected"}), 200
        else:
            return jsonify({"error": "Failed to reject assignment"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/data/set-model-answer-paper", methods=["POST"])
def set_model_answer_paper():
    try:
        data_from_frontend = request.json
        paper_id = data_from_frontend["paperId"]
        existing_paper = mongo.db.TeacherModelAnswerPaper.find_one(
            {"paperId": paper_id}
        )
        if existing_paper:
            mongo.db.TeacherModelAnswerPaper.update_one(
                {"paperId": paper_id}, {"$set": data_from_frontend}
            )
        else:
            mongo.db.TeacherModelAnswerPaper.insert_one(data_from_frontend)

        return jsonify({"message": "Data saved successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/api/data/evaluaed-answers-of-student", methods=["POST"])
def evaluaed_answers_of_student():
    data = request.json
    answers_cursor = mongo.db.evaluated.find_one(
            {
                "email": data["email"],
                "seatNumber": data["seatNumber"],
                "paperId": data["paperId"],
                "rollNumber": data["rollNumber"],
            }
        )
    if answers_cursor:
        answers_cursor = json_util.dumps(answers_cursor)
        return answers_cursor, 200
    else:
        return jsonify({"error": "No papers data found"}), 404
    
@app.route("/api/data/evaluaed-answers-of-student-pdf", methods=["POST"])
def evaluaed_answers_of_student_pdf():
    data = request.json
    print(data)
    answers_cursor = mongo.db.evaluatedPDF.find_one(
            {
               
                "paperId": data["paperId"],

            }
        )
    print(answers_cursor)
    if answers_cursor:
        answers_cursor = json_util.dumps(answers_cursor)
        return answers_cursor, 200
    else:
        return jsonify({"error": "No papers data found"}), 404

@app.route('/api/data/fsfiles/<string:paper_id>', methods=['GET'])
def get_all_pdfs(paper_id):
    print(paper_id)
    pdfs = mongo.db['fs.files'].find({'paperId': paper_id})
    print(paper_id)
    pdf_list = []
    for pdf in pdfs:
        pdf['_id'] = str(pdf['_id'])
        pdf_list.append(pdf)

    return jsonify(pdf_list)

# Route to fetch binary data of a specific PDF file by ID
@app.route('/api/data/fsfiles/open/<id>', methods=['GET'])
def get_pdf_by_id(id):
    # Find the PDF file in the 'fs.files' collection by its ID
    pdf = mongo.db['fs.files'].find_one({'_id': ObjectId(id)})

    # If the PDF file is found, return it with binary data
    if pdf:
        # Fetch binary data of the PDF file
        pdf_data = mongo.db['fs.chunks'].find({'files_id': ObjectId(id)})
        binary_data = b''
        for chunk in pdf_data:
            binary_data += chunk['data']

        # Return the binary data as a response with appropriate MIME type
        return Response(binary_data, mimetype='application/pdf')
    else:
        return jsonify({'error': 'PDF not found'}), 404

@app.route("/api/return-model-answer/<string:paper_id>", methods=["GET"])
def return_model_paper_existence(paper_id):
    try:
        paper_object_id = paper_id
        print('paperid model : ', paper_object_id)
        paper_exists = mongo.db.TeacherModelAnswerPaper.find_one(
            {"paperId": paper_object_id}
        )
        print('check th e data exist for model paper: ', paper_exists)
        if paper_exists :
            print('model paper exit and sucess')
            print("model answer: ", paper_exists)
            return jsonify(paper_exists), 200
        else:
            print('Modi: Bhen ke Lodee !!')
            return (
                jsonify({"exists": False}),
                404,
            )  # Assuming 404 is appropriate for paper not found
    except Exception as e:
        return jsonify({"error": "An error occurred while processing the request"}), 500

if __name__ == "__main__":
    app.run(debug=True)
