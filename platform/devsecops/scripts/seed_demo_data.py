import json, random, os
import boto3
from faker import Faker

fake = Faker()
s3 = boto3.client("s3")

DEMO_BUCKET = os.environ["DEMO_BUCKET"]

def fake_ssn():
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"

def make_sensitive_record():
    name = fake.name()
    address = fake.address()
    ssn = fake_ssn()
    dob = str(fake.date_of_birth())
    phone = fake.phone_number()
    note = "Patient reports chest pain and shortness of breath."

    record = {
        "name": name,
        "address": address,
        "ssn": ssn,
        "dob": dob,
        "phone": phone,
        "note": note,
    }

    # RAG-friendly field used by sync_s3_rag_to_pinecone
    record["text"] = (
        f"SENSITIVE MEDICAL NOTE\n"
        f"Name: {name}\n"
        f"Address: {address}\n"
        f"SSN: {ssn}\n"
        f"DOB: {dob}\n"
        f"Phone: {phone}\n"
        f"Note: {note}"
    )

    return record


def make_clean_record():
    service = "limo booking"
    city = fake.city()
    date = str(fake.date_this_year())
    notes = "Customer asked about availability."

    record = {
        "service": service,
        "city": city,
        "date": date,
        "notes": notes,
    }

    # RAG-friendly field used by sync_s3_rag_to_pinecone
    record["text"] = (
        f"CLEAN SERVICE RECORD\n"
        f"Service: {service}\n"
        f"City: {city}\n"
        f"Date: {date}\n"
        f"Notes: {notes}"
    )

    return record

def upload(prefix, filename, body):
    key = f"{prefix}/{filename}"
    s3.put_object(Bucket=DEMO_BUCKET, Key=key, Body=json.dumps(body, indent=2).encode("utf-8"))
    print("uploaded", key)

def main():
    # clean docs
    for i in range(5):
        upload("clean", f"clean_{i}.json", make_clean_record())

    # sensitive docs
    for i in range(5):
        upload("sensitive", f"sensitive_{i}.json", make_sensitive_record())

if __name__ == "__main__":
    main()
