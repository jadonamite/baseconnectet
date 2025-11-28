import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/providers/AuthProvider";
import { useAccount, useSignMessage, useChainId } from "wagmi";
import { useState, useCallback, useRef, useEffect } from "react";

interface AuthError extends Error {
  code?: string;
  statusCode?: number;
}

interface NonceResponse {
  nonce: string;
  expiresAt: number;
}

interface VerifyResponse {
  token: string;
  user: {
    id: string;
    walletAddress: string;
    // ... other user fields
  };
}

export const useWalletAuth = () => {
  const { toast } = useToast();
  const { refresh } = useAuth();
  const { address, isConnected } = useAccount();
  const chainId = useChainId();
  const { signMessageAsync } = useSignMessage();

  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [error, setError] = useState<AuthError | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  const authenticateWithWallet = useCallback(async () => {
    // Prevent multiple simultaneous auth attempts
    if (isAuthenticating) {
      console.warn("Authentication already in progress");
      return;
    }

    // Reset state
    setError(null);
    setIsAuthenticating(true);

    // Create abort controller for this request
    abortControllerRef.current = new AbortController();
    const signal = abortControllerRef.current.signal;

    try {
      // Validation
      if (!isConnected || !address) {
        throw new Error("Please connect your wallet before continuing");
      }

      if (!chainId) {
        throw new Error("Could not determine network. Please check your wallet connection");
      }

      const walletAddress = address.toLowerCase();
      const API_URL = import.meta.env.VITE_API_URL;

      if (!API_URL) {
        throw new Error("API configuration missing. Please contact support");
      }

      // 1️⃣ Request nonce from backend with timeout
      const nonceRes = await fetchWithTimeout(
        `${API_URL}/api/auth/wallet/request`,
        {
          method: "POST",
          headers: { 
            "Content-Type": "application/json",
            "X-Client-Version": "1.0.0", // For version tracking
          },
          body: JSON.stringify({ 
            walletAddress,
            chainId, // Include chain ID for validation
          }),
          signal,
        },
        10000 // 10 second timeout
      );

      const nonceData: NonceResponse = await nonceRes.json();
      
      if (!nonceRes.ok) {
        const error: AuthError = new Error(nonceData.message || "Failed to request nonce");
        error.statusCode = nonceRes.status;
        throw error;
      }

      // Validate nonce
      if (!nonceData.nonce || typeof nonceData.nonce !== "string") {
        throw new Error("Invalid nonce received from server");
      }

      // Check if nonce expired (if backend sends expiry)
      if (nonceData.expiresAt && Date.now() > nonceData.expiresAt) {
        throw new Error("Authentication nonce expired. Please try again");
      }

      // 2️⃣ Create more robust message with context
      const timestamp = Date.now();
      const message = [
        "BaseConnect Authentication",
        `Wallet: ${walletAddress}`,
        `Chain ID: ${chainId}`,
        `Nonce: ${nonceData.nonce}`,
        `Timestamp: ${timestamp}`,
        "",
        "Sign this message to authenticate your wallet.",
        "This will not trigger any blockchain transaction or cost gas fees."
      ].join("\n");

      // 3️⃣ Sign the message
      let signature: string;
      try {
        signature = await signMessageAsync({ message });
      } catch (signError) {
        // User rejected signature
        if (signError instanceof Error && signError.message.includes("User rejected")) {
          throw new Error("Signature request was rejected");
        }
        throw new Error("Failed to sign message. Please try again");
      }

      // 4️⃣ Verify signed message with backend
      const verifyRes = await fetchWithTimeout(
        `${API_URL}/api/auth/wallet/verify`,
        {
          method: "POST",
          headers: { 
            "Content-Type": "application/json",
            "X-Client-Version": "1.0.0",
          },
          body: JSON.stringify({ 
            walletAddress,
            chainId,
            signature,
            message, // Send original message for verification
            timestamp,
          }),
          signal,
        },
        10000
      );

      const verifyData: VerifyResponse = await verifyRes.json();
      
      if (!verifyRes.ok) {
        const error: AuthError = new Error(verifyData.message || "Wallet authentication failed");
        error.statusCode = verifyRes.status;
        throw error;
      }

      // Validate token
      if (!verifyData.token || typeof verifyData.token !== "string") {
        throw new Error("Invalid authentication token received");
      }

      // 5️⃣ Store JWT in httpOnly cookie (if backend supports) or sessionStorage
      // BETTER: Let backend set httpOnly cookie, don't store in frontend
      // If you must store client-side, use sessionStorage (cleared on tab close)
      sessionStorage.setItem("authToken", verifyData.token);
      
      // Set auth header for subsequent requests
      // Better to handle this in axios/fetch interceptor
      
      // Refresh auth state
      await refresh();

      // 6️⃣ Kickoff verification (move to backend for security)
      // This should be done server-side to protect API keys
      try {
        await fetch(`${API_URL}/api/integrations/kickoff/verify`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${verifyData.token}`,
          },
          body: JSON.stringify({
            taskType: "connect_wallet",
          }),
          signal,
        });
      } catch (kickoffError) {
        // Log but don't fail authentication
        console.warn("Kickoff verification error:", kickoffError);
      }

      toast({
        title: "Wallet Connected",
        description: `Successfully authenticated with ${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}`,
      });

      return verifyData.user;

    } catch (error) {
      // Don't show error if request was aborted (component unmounted)
      if (error instanceof Error && error.name === "AbortError") {
        console.log("Authentication request cancelled");
        return;
      }

      console.error("Wallet authentication error:", error);
      
      const authError = error as AuthError;
      setError(authError);

      // More specific error messages
      let errorTitle = "Wallet Authentication Failed";
      let errorDescription = "Please try again";

      if (authError.statusCode === 429) {
        errorTitle = "Too Many Attempts";
        errorDescription = "Please wait a moment before trying again";
      } else if (authError.statusCode === 401) {
        errorDescription = "Invalid signature. Please try again";
      } else if (authError.message.includes("network")) {
        errorDescription = "Network error. Please check your connection";
      } else if (authError.message) {
        errorDescription = authError.message;
      }

      toast({
        title: errorTitle,
        description: errorDescription,
        variant: "destructive",
      });
      
      throw error;
      
    } finally {
      setIsAuthenticating(false);
      abortControllerRef.current = null;
    }
  }, [address, chainId, isConnected, isAuthenticating, refresh, signMessageAsync, toast]);

  // Helper to cancel ongoing authentication
  const cancelAuthentication = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      setIsAuthenticating(false);
    }
  }, []);

  return { 
    authenticateWithWallet,
    cancelAuthentication,
    isAuthenticating,
    error,
  };
};

// Utility function for fetch with timeout
async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeout: number
): Promise<Response> {
  const controller = new AbortController();
  const signal = options.signal || controller.signal;
  
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, { ...options, signal });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error("Request timed out. Please try again");
    }
    throw error;
  }
}
