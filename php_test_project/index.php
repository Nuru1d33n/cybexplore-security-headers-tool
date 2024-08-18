<?php
$page = isset($_GET['page']) ? $_GET['page'] : 'home';

header('X-Frame-Options: ALLOW');
header('X-XSS-Protection: 1; mode=block');
header('X-Content-Type-Options: nosniff');
header('Content-Security-Policy: default-src \'self\';');
header('Referrer-Policy: no-referrer');

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="generator" content="WordPress 5.8.1">
    <title>Home - My PHP Project</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <h1>Welcome to My PHP Project</h1>
        <nav>
            <ul>
                <li><a href="?page=home">Home</a></li>
                <li><a href="?page=about">About</a></li>
                <li><a href="?page=contact">Contact</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <?php
        if ($page == 'home') {
            echo "<h2>Home Page</h2><p>This is the home page.</p>";
        } elseif ($page == 'about') {
            include 'about.php';
        } elseif ($page == 'contact') {
            include 'contact.php';
        } else {
            echo "<h2>404 Not Found</h2><p>The page you are looking for does not exist.</p>";
        }
        ?>
    </main>

    <footer>
        <p>&copy; 2024 My PHP Project</p>
    </footer>
</body>
</html>
