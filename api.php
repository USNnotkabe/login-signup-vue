<?php
require 'dbconnection.php';

header("Access-Control-Allow-Origin: *");
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Methods: POST');
header("Content-Type: application/json");


$method = $_SERVER['REQUEST_METHOD'];
$input = json_decode(file_get_contents('php://input'), true);

if ($method === 'POST') {
    if (!isset($input['action'])) {
        echo json_encode(["message" => "No action specified"]);
        exit;
    }   

    $action = $input['action'];
    
    if ($action === 'register') {
 
        $name = $input['name'] ?? '';
        $address = $input['address'] ?? '';
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';

        if (!$name || !$address || !$username || !$password) {
            echo json_encode(["message" => "All fields are required"]);
            exit;
        }

    
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $pdo->prepare("INSERT INTO registration (name, address, username, password) VALUES (?, ?, ?, ?)");
        $success = $stmt->execute([$name, $address, $username, $hashedPassword]);

        if ($success) {
            echo json_encode(["message" => "Registration successful"]);
        } else {
            echo json_encode(["message" => "Registration failed"]);
        }

    } elseif ($action === 'login') {
   
        $username = $input['username'] ?? '';
        $password = $input['password'] ?? '';

        if (!$username || !$password) {
            echo json_encode(["message" => "Username and password required"]);
            exit;
        }

        $stmt = $pdo->prepare("SELECT * FROM registration WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            echo json_encode([
                "message" => "Login successful",
                "user" => [
                    "id" => $user['id'],
                    "name" => $user['name'],
                    "address" => $user['address'],
                    "username" => $user['username']
                ]
            ]);
        } else {
            echo json_encode(["message" => "Invalid username or password"]);
        }

    } else {
        echo json_encode(["message" => "Invalid action"]);
    }

} else {
    echo json_encode(["message" => "Invalid request method"]);
}
?>