<?php
/**
 * 资源获取接口
 * 用于安全地传输 protected 目录下的资源文件
 */

session_start();

// 快速检查验证状态（不加载完整 session.php）
if (!isset($_SESSION['verified']) || $_SESSION['verified'] !== true) {
    http_response_code(403);
    exit('Access Denied');
}

// 获取请求的文件路径
$file = isset($_GET['f']) ? $_GET['f'] : '';

if (empty($file)) {
    http_response_code(400);
    exit('Bad Request');
}

// 安全检查：防止目录遍历攻击
$file = str_replace(['../', '..\\', '..'], '', $file);
$file = ltrim($file, '/\\');

// 构建文件路径
$filePath = __DIR__ . '/../protected/' . $file;

// 检查文件是否存在
if (!file_exists($filePath) || is_dir($filePath)) {
    http_response_code(404);
    exit('Not Found');
}

// 获取文件 MIME 类型
$mimeTypes = [
    'html' => 'text/html',
    'css' => 'text/css',
    'js' => 'application/javascript',
    'json' => 'application/json',
    'png' => 'image/png',
    'jpg' => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'gif' => 'image/gif',
    'svg' => 'image/svg+xml',
    'ico' => 'image/x-icon',
    'webp' => 'image/webp',
    'woff' => 'font/woff',
    'woff2' => 'font/woff2',
    'ttf' => 'font/ttf',
    'eot' => 'application/vnd.ms-fontobject',
    'mp4' => 'video/mp4',
    'webm' => 'video/webm',
    'mp3' => 'audio/mpeg',
    'pdf' => 'application/pdf',
    'zip' => 'application/zip',
];

$ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
$mime = isset($mimeTypes[$ext]) ? $mimeTypes[$ext] : 'application/octet-stream';

// 获取文件修改时间用于缓存
$mtime = filemtime($filePath);
$etag = md5($filePath . $mtime);

// 检查客户端缓存
if (isset($_SERVER['HTTP_IF_NONE_MATCH']) && $_SERVER['HTTP_IF_NONE_MATCH'] === $etag) {
    http_response_code(304);
    exit;
}
if (isset($_SERVER['HTTP_IF_MODIFIED_SINCE']) && strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) >= $mtime) {
    http_response_code(304);
    exit;
}

// 设置响应头（启用浏览器缓存）
header('Content-Type: ' . $mime);
header('Content-Length: ' . filesize($filePath));
header('Cache-Control: private, max-age=86400'); // 缓存1天
header('ETag: ' . $etag);
header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $mtime) . ' GMT');

// 支持 Range 请求（视频大文件）
if (isset($_SERVER['HTTP_RANGE'])) {
    $size = filesize($filePath);
    $range = $_SERVER['HTTP_RANGE'];
    $range = str_replace('bytes=', '', $range);
    list($start, $end) = explode('-', $range);
    $start = intval($start);
    $end = $end === '' ? $size - 1 : intval($end);
    $length = $end - $start + 1;
    
    header('HTTP/1.1 206 Partial Content');
    header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
    header('Content-Length: ' . $length);
    
    $fp = fopen($filePath, 'rb');
    fseek($fp, $start);
    $buffer = 1024 * 1024; // 1MB buffer
    $sent = 0;
    while ($sent < $length && !feof($fp)) {
        $read = min($buffer, $length - $sent);
        echo fread($fp, $read);
        $sent += $read;
    }
    fclose($fp);
} else {
    // 普通请求，直接输出
    readfile($filePath);
}
exit;
