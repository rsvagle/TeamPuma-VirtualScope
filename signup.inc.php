<?php
if (isset($_POST['signup-submit'])) {
	
	require 'dbh.inc.php';

	//fetch info from the sign up form from user
	$name = $_POST['name']; 
	$classpwd = $_POST['classpwd'];
	$username = $_POST['uid'];
	$password = $_POST['pwd'];
	$email = $_POST['mail'];
	$passwordRepeat = $_POST['pwd-repeat'];

	//user input error handling

	if(empty($username) || empty($name) || empty($password) ||empty($email) ||empty($passwordRepeat) || empty($classpwd)){
		header("Location: ../signup.php?error=emptyfields&uid=".$username."&mail".$email);
		exit();
	}

	else if(!filter_var($email, FILTER_VALIDATE_EMAIL) && !preg_match("/^[a-zA-Z0-9]*$/", $username)){
		header("Location: ../signup.php?error=invalidmailuid");
		exit();
	}

	else if(!filter_var($email, FILTER_VALIDATE_EMAIL)){
		header("Location: ../signup.php?error=invalidmail&uid=".$username);
		exit();
	}
	else if(!preg_match("/^[a-zA-Z0-9]*$/", $username)){
		header("Location: ../signup.php?error=invaliduid&email=".$email);
		exit();
	}
	//checks to see if password and repeatpassword are the same
	else if($password !== $passwordRepeat){
		header("Location: ../signup.php?error=passwordcheck&uid=".$username."&mail".$email);
		exit();

	}
	else{
		//not in else if because will need to check at all time to 
		//make sure the user does not use a username already in used
		//done in a safe way with prepared statement without risking security
		//done so with place holder ?
		$sql = "SELECT uidUsers FROM users WHERE uidUSERS=?";
		$stmt = mysqli_stmt_init($conn);

		if(!mysqli_stmt_prepare($stmt, $sql)){
			header("Location: ../signup.php?error=sqlerror");
			exit();
		}
		else{
			//take infor from user gave us and put in the database 
			//passed in with stmt and the type string
			mysqli_stmt_bind_param($stmt, "s", $username);
			//passing more than one param
			//($stmt, "ss", $username, $pwd)
			//execute statment into the database
			mysqli_stmt_execute($stmt);
			//now need to check if there is a match
			//by storing results in $stmt
			mysqli_stmt_store_result($stmt);
			$resultCheck = mysqli_stmt_num_rows($stmt);
			//should be zero or 1
			if ($resultCheck>0) {
				header("Location: ../signup.php?error=usertaken&mail=".$email);
				exit();
			}
			else{
				$sql = "INSERT INTO users (uidUsers, emailUsers, pwdUsers) VALUES (?,?,?)";
				$stmt = mysqli_stmt_init($conn);

				if(!mysqli_stmt_prepare($stmt, $sql)){
				header("Location: ../signup.php?error=sqlerror");
				exit();
				}
				else{
					//hash password first then insert new user info record
					//hashing with b crypt
					//don't use outdated hasing such as SHA or MD6
					$hashPwd = password_hash($password, PASSWORD_DEFAULT);
					mysqli_stmt_bind_param($stmt, "sss", $username, $email, $hashPwd);
					mysqli_stmt_execute($stmt);

					header("Location: ../index.php");
					exit();

					
				}
			} 


		}

	}
	msqli_stmt_close($stmt);
	msqli_close($conn);

}

else{
	//if user did not access the page through the normal way without clicking the signup button
	header("Location: ../signup.php");
	exit();
}