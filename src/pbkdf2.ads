with Ada.Streams; use Ada.Streams;

with GNAT.SHA1;

package PBKDF2 is
    function PBKDF2_HMAC_SHA1 (Password : String; Salt : String; Iterations : Natural; Derived_Length : Stream_Element_Offset := GNAT.SHA1.Hash_Length)
        return Stream_Element_Array;
end PBKDF2;