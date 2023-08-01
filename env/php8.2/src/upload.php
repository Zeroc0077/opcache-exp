<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $file_name = $_FILES['file']['name'];
    $file_size = $_FILES['file']['size'];
    $file_tmp = $_FILES['file']['tmp_name'];
    $file_type = $_FILES['file']['type'];
    
    $upload_path = $_POST['upload_path'];
    if (empty($upload_path)) {
        echo "请指定上传路径！";
        exit;
    }
    
    if (!file_exists($upload_path)) {
        mkdir($upload_path, 0777, true);
    }
    
    $file_destination = $upload_path . '/' . $file_name;
    move_uploaded_file($file_tmp, $file_destination);
    
    echo "文件上传成功！";
}
?>