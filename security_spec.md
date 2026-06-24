# Security Specification: Firestore Rules Security TDD

This specification defines the security invariants and testing payloads for our Firestore database collections.

## 1. Data Invariants

1. **User Profiles (`/users/{userId}`)**:
   - Users can only read and write their own profile document (`request.auth.uid == userId`).
   - The user's registration `role` cannot be escalated or modified by the user themselves; only admins can modify or assign roles.
   - Profile documents must contain a matching `uid` field equal to `request.auth.uid`.

2. **Test Attempts (`/test_attempts/{attemptId}`)**:
   - A student can only submit a test attempt under their own authenticated UID (`request.auth.uid == resource.data.userUid` or `incoming().userUid`).
   - Attempts are append-only (cannot be modified or deleted by the student after submission).
   - Non-premium students cannot access or save premium test metrics.

3. **Live Doubts (`/live_doubts/{doubtId}`)**:
   - Students can create doubts under their own name/UID (`incoming().studentUid == request.auth.uid`).
   - Students can read their own doubts.
   - Instructors and Admins can view all doubts and update them with replies and change status to `resolved`.
   - Students cannot edit or reply to queries after creation.

---

## 2. The "Dirty Dozen" Payloads (Designed to Fail)

Below are 12 specific payloads that are mathematically guaranteed to return `PERMISSION_DENIED` under our fortress security model.

### 1. Self-Assigned Administrator Role (Privilege Escalation)
- **Path**: `/users/attacker_uid`
- **Operation**: `create` or `update`
- **Payload**:
  ```json
  {
    "uid": "attacker_uid",
    "name": "Attacker",
    "email": "attacker@gmail.com",
    "role": "admin",
    "isPremium": true
  }
  ```
- **Reason for rejection**: Regular users are forbidden from creating or updating their roles to `admin` or `instructor`.

### 2. Impersonated User Profile Injection
- **Path**: `/users/victim_uid`
- **Operation**: `create`
- **Payload**:
  ```json
  {
    "uid": "victim_uid",
    "name": "Victim",
    "email": "victim@gmail.com",
    "role": "student",
    "isPremium": false
  }
  ```
- **Authenticated User**: `attacker_uid`
- **Reason for rejection**: The document ID must match the authenticated user's UID (`request.auth.uid == userId`).

### 3. Spoofed UID in Test Attempt
- **Path**: `/test_attempts/attempt_abc`
- **Operation**: `create`
- **Payload**:
  ```json
  {
    "id": "attempt_abc",
    "testId": "algebra_01",
    "testTitle": "Algebra Quiz",
    "examCategory": "SSC",
    "userUid": "victim_uid",
    "userName": "Victim Student",
    "rollNumber": "VIB-1002",
    "score": 100,
    "totalMarks": 100,
    "correctAnswers": 50,
    "incorrectAnswers": 0,
    "unattemptedAnswers": 0,
    "timeSpentSeconds": 120,
    "completedAt": "2026-06-24T14:12:00Z"
  }
  ```
- **Authenticated User**: `attacker_uid`
- **Reason for rejection**: The `userUid` property in the test attempt payload must match the authenticated user (`request.auth.uid`).

### 4. Attempt to Modify a Submitted Test Score (Immutability Violation)
- **Path**: `/test_attempts/attempt_abc`
- **Operation**: `update`
- **Payload**:
  ```json
  {
    "score": 100
  }
  ```
- **Reason for rejection**: Test attempts are strictly read-only after creation; updates are denied.

### 5. Anonymous Doubt Post (Unverified User)
- **Path**: `/live_doubts/doubt_999`
- **Operation**: `create`
- **Payload**:
  ```json
  {
    "id": "doubt_999",
    "studentUid": "anonymous_uid",
    "studentName": "Anonymous",
    "studentRoll": "VIB-9999",
    "subject": "Maths",
    "message": "Is 1+1=2?",
    "status": "open",
    "createdAt": "2026-06-24T14:12:00Z"
  }
  ```
- **Authenticated User**: None (or unverified/anonymous)
- **Reason for rejection**: Must be an authenticated, verified student to write doubts.

### 6. Student Self-Replying/Resolving a Doubt (Privilege Violation)
- **Path**: `/live_doubts/doubt_abc`
- **Operation**: `update`
- **Payload**:
  ```json
  {
    "reply": "Self solved! It is simple.",
    "repliedBy": "Attacker student",
    "status": "resolved"
  }
  ```
- **Authenticated User**: `student_uid` (author of the doubt)
- **Reason for rejection**: Only admins or instructors are allowed to update doubts with replies.

### 7. Large String Resource Poisoning in Doubt Message (Denial of Wallet)
- **Path**: `/live_doubts/doubt_abc`
- **Operation**: `create`
- **Payload**:
  ```json
  {
    "id": "doubt_abc",
    "studentUid": "student_uid",
    "studentName": "Student",
    "studentRoll": "VIB-1002",
    "subject": "Maths",
    "message": "[A 5 Megabyte string repeat...]",
    "status": "open",
    "createdAt": "2026-06-24T14:12:00Z"
  }
  ```
- **Reason for rejection**: Rules enforce a max size length of strings (e.g. `message.size() <= 2000`).

### 8. Attempting to Read Other Student's Test Attempts
- **Path**: `/test_attempts/victim_attempt`
- **Operation**: `get`
- **Authenticated User**: `attacker_uid`
- **Reason for rejection**: Students are only permitted to retrieve and view their own test attempts.

### 9. Unauthorized Doubt Status Hijacking
- **Path**: `/live_doubts/doubt_xyz`
- **Operation**: `update`
- **Payload**:
  ```json
  {
    "status": "resolved"
  }
  ```
- **Authenticated User**: `attacker_student_uid` (not the assigned tutor or admin)
- **Reason for rejection**: Regular students have zero update privileges on doubt documents.

### 10. Attempting to Delete a Live Doubt (Audit Escape)
- **Path**: `/live_doubts/doubt_abc`
- **Operation**: `delete`
- **Authenticated User**: `student_uid`
- **Reason for rejection**: Live doubts cannot be deleted by students to maintain academic audit logs.

### 11. Malformed Date-Time Format Injection
- **Path**: `/live_doubts/doubt_xyz`
- **Operation**: `create`
- **Payload**:
  ```json
  {
    "id": "doubt_xyz",
    "studentUid": "student_uid",
    "studentName": "Student",
    "studentRoll": "VIB-1002",
    "subject": "Maths",
    "message": "Valid question?",
    "status": "open",
    "createdAt": "Not a timestamp!"
  }
  ```
- **Reason for rejection**: The `createdAt` must be a valid timestamp matched against `request.time`.

### 12. Unsigned/Anonymous Read of User Profiles (Scraping Guard)
- **Path**: `/users/any_user_uid`
- **Operation**: `get` or `list`
- **Authenticated User**: None / Unsigned
- **Reason for rejection**: Reading user profiles requires active authenticated session verification.

---

## 3. Test Runner Concept

A local integration testing structure will verify these cases against the Local Emulator during builds, ensuring zero regression across core schemas.
