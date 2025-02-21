<?php
class SafeGuard_AI_Analyzer {
    private $api_endpoint = 'http://194.163.170.136:8000/analyze';
    private $last_error = null;

    public function analyze_request($request_data) {
        try {
            // Prepare the request data
            $data = array(
                'ip' => $request_data['ip'] ?? $_SERVER['REMOTE_ADDR'],
                'method' => $request_data['method'] ?? $_SERVER['REQUEST_METHOD'],
                'uri' => $request_data['uri'] ?? $_SERVER['REQUEST_URI'],
                'query' => $request_data['query'] ?? $_SERVER['QUERY_STRING'],
                'post' => $request_data['post'] ?? file_get_contents('php://input'),
                'headers' => $this->get_request_headers(),
                'timestamp' => time()
            );

            // Make the API request
            $response = wp_remote_post($this->api_endpoint, array(
                'timeout' => 5,
                'headers' => array('Content-Type' => 'application/json'),
                'body' => wp_json_encode($data)
            ));

            if (is_wp_error($response)) {
                error_log('SafeGuardWP AI Analysis Error: ' . $response->get_error_message());
                return false;
            }

            $body = wp_remote_retrieve_body($response);
            $result = json_decode($body, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                error_log('SafeGuardWP AI Analysis Error: Invalid JSON response');
                return false;
            }

            return $this->process_ai_response($result);

        } catch (Exception $e) {
            error_log('SafeGuardWP AI Analysis Exception: ' . $e->getMessage());
            $this->last_error = $e->getMessage();
            return false;
        }
    }

    private function get_request_headers() {
        $headers = array();
        foreach ($_SERVER as $key => $value) {
            if (substr($key, 0, 5) === 'HTTP_') {
                $header = str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($key, 5)))));
                $headers[$header] = $value;
            }
        }
        return $headers;
    }

    private function process_ai_response($result) {
        if (!isset($result['analysis'])) {
            return array(
                'is_threat' => false,
                'confidence' => 0,
                'type' => 'unknown',
                'details' => array()
            );
        }

        return array(
            'is_threat' => $result['analysis']['is_threat'] ?? false,
            'confidence' => $result['analysis']['confidence'] ?? 0,
            'type' => $result['analysis']['type'] ?? 'unknown',
            'details' => $result['analysis']['details'] ?? array()
        );
    }

    public function get_last_error() {
        return $this->last_error;
    }
}
