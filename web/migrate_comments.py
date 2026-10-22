"""Encrypt existing PostgreSQL comments using the application's persistent key.

Run during the guided migration, with the old web service stopped.
The entire migration commits or rolls back as one transaction.
"""

import os
import sys

import psycopg2

from comment_crypto import PREFIX, load_key, encrypt_comment, decrypt_comment


def migrate_comments():
    key = load_key()
    conn = psycopg2.connect(
        host=os.environ["DB_HOST"],
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
    )
    encrypted_count = 0
    verified_count = 0
    try:
        with conn.cursor() as cur:
            cur.execute("LOCK TABLE notes IN SHARE ROW EXCLUSIVE MODE")
            cur.execute("SELECT id, comment FROM notes WHERE comment IS NOT NULL FOR UPDATE")
            for note_id, value in cur.fetchall():
                if value.startswith(PREFIX):
                    # Validate existing ciphertext with this key before skipping it.
                    decrypt_comment(value, note_id, key)
                    verified_count += 1
                else:
                    encrypted = encrypt_comment(value, note_id, key)
                    cur.execute(
                        "UPDATE notes SET comment = %s WHERE id = %s",
                        (encrypted, note_id),
                    )
                    encrypted_count += 1
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return encrypted_count, verified_count


if __name__ == "__main__":
    try:
        encrypted, verified = migrate_comments()
    except Exception as exc:
        # Report the error category without printing keys or comment contents.
        print(
            "Migration failed; this transaction was rolled back. "
            f"Error type: {type(exc).__name__}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"Migration complete: encrypted {encrypted}; verified {verified} existing encrypted comments.")
