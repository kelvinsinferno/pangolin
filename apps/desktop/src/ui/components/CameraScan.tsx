// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';

export interface CameraScanProps {
  /** Fired once with the decoded QR text (the base64 transport blob). */
  onResult: (text: string) => void;
  /** Fired when the camera is unavailable / denied / errors. The UI
   *  degrades to paste (L3 — never blocks the flow on a missing camera). */
  onUnavailable?: (message: string) => void;
}

/**
 * Camera QR scanner (MVP-4-I Q-a Option 3).
 *
 * Requests `getUserMedia`, draws frames to an offscreen canvas, and runs
 * `jsQR` until it decodes a symbol — then fires `onResult` once and stops.
 * No frame ever leaves the device (decode is in-process; the stream is
 * stopped on unmount / first result). If the camera is unsupported or the
 * permission is denied it renders an inline note and fires `onUnavailable`
 * so the parent shows the paste fallback.
 *
 * Camera capture is NOT exercised in CI (jsdom has no `getUserMedia`); the
 * §9 manual smoke test is the proof. The tested path is the
 * unavailable-fallback.
 */
export function CameraScan({ onResult, onUnavailable }: CameraScanProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const onResultRef = useRef(onResult);
  onResultRef.current = onResult;
  const onUnavailableRef = useRef(onUnavailable);
  onUnavailableRef.current = onUnavailable;
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    let stream: MediaStream | null = null;
    let raf = 0;
    let cancelled = false;
    let fired = false;
    const canvas = document.createElement('canvas');

    const stop = () => {
      cancelled = true;
      if (raf !== 0) cancelAnimationFrame(raf);
      stream?.getTracks().forEach((t) => t.stop());
    };

    const tick = () => {
      const video = videoRef.current;
      if (cancelled || fired || video === null) return;
      if (video.readyState >= video.HAVE_ENOUGH_DATA && video.videoWidth > 0) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d');
        if (ctx !== null) {
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(img.data, img.width, img.height);
          if (code !== null && code.data !== '') {
            fired = true;
            onResultRef.current(code.data);
            stop();
            return;
          }
        }
      }
      raf = requestAnimationFrame(tick);
    };

    const start = async () => {
      const md = navigator.mediaDevices;
      if (md === undefined || typeof md.getUserMedia !== 'function') {
        setUnavailable(true);
        onUnavailableRef.current?.('camera not available on this device');
        return;
      }
      try {
        stream = await md.getUserMedia({ video: { facingMode: 'environment' } });
      } catch {
        if (!cancelled) {
          setUnavailable(true);
          onUnavailableRef.current?.('camera permission denied');
        }
        return;
      }
      if (cancelled) {
        stream.getTracks().forEach((t) => t.stop());
        return;
      }
      const video = videoRef.current;
      if (video === null) return;
      video.srcObject = stream;
      try {
        await video.play();
      } catch {
        // Autoplay can reject; the frame loop still runs once data is ready.
      }
      raf = requestAnimationFrame(tick);
    };

    void start();
    return stop;
  }, []);

  if (unavailable) {
    return (
      <p className="code-ingest__camera-note" role="status">
        Camera unavailable — paste the code instead.
      </p>
    );
  }

  return (
    <video
      ref={videoRef}
      className="code-ingest__camera"
      muted
      playsInline
      aria-label="Camera viewfinder for scanning a pairing code"
    />
  );
}
