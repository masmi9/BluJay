export interface Screenshot {
  id: number
  session_id: number
  captured_at: string
  label: string
  file_path: string
  thumbnail_b64: string
}

export interface CaptureRequest {
  serial: string
  session_id: number
  label: string
}
