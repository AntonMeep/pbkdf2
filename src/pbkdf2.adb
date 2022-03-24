pragma Ada_2012;

with Interfaces;

with System;

package body PBKDF2 is
   function Write_Big_Endian
     (Input : Stream_Element_Offset) return Stream_Element_Array
   is
      use Interfaces;
      use System;

      Int : constant Unsigned_32 := Unsigned_32 (Input);
   begin
      if Default_Bit_Order = High_Order_First then
         return
           (0 => Stream_Element (Int and 16#FF#),
            1 => Stream_Element (Shift_Right (Int, 8) and 16#FF#),
            2 => Stream_Element (Shift_Right (Int, 16) and 16#FF#),
            3 => Stream_Element (Shift_Right (Int, 24) and 16#FF#));
      else
         return
           (0 => Stream_Element (Shift_Right (Int, 24) and 16#FF#),
            1 => Stream_Element (Shift_Right (Int, 16) and 16#FF#),
            2 => Stream_Element (Shift_Right (Int, 8) and 16#FF#),
            3 => Stream_Element (Int and 16#FF#));
      end if;
   end Write_Big_Endian;

   procedure XOR_In_Place
     (L : in out Stream_Element_Array; R : Stream_Element_Array)
   is
   begin
      pragma Assert (L'Length = R'Length);

      for I in L'Range loop
         L (I) := L (I) xor R (I);
      end loop;
   end XOR_In_Place;

   generic
      type Context (<>) is private;
      with function HMAC_Init (Password : String) return Context;
      with procedure HMAC_Update_Salt (Ctx : in out Context; Salt : String);
      with procedure HMAC_Update_Data
        (Ctx : in out Context; Data : Stream_Element_Array);
      with function HMAC_Final (Ctx : in out Context) return Stream_Element_Array;

      Hash_Length : Stream_Element_Offset;
   function PBKDF2_Implementation
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset) return Stream_Element_Array;

   function PBKDF2_Implementation
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset) return Stream_Element_Array
   is
      Result  : Stream_Element_Array (1 .. Derived_Key_Length);
      Current : Stream_Element_Offset := Result'First;

      Blocks_Needed : constant Stream_Element_Offset :=
        Stream_Element_Offset
          (Float'Ceiling (Float (Derived_Key_Length) / Float (Hash_Length)));
   begin
      for Index in 1 .. Blocks_Needed loop
         declare
            Ctx : Context := HMAC_Init (Password);

            Temporary, Last : Stream_Element_Array (1 .. Hash_Length);
         begin
            --  First iteration
            HMAC_Update_Salt (Ctx, Salt);
            HMAC_Update_Data (Ctx, Write_Big_Endian (Index));
            Temporary := HMAC_Final (Ctx);
            Last      := Temporary;

            --  Subsequent iterations
            for Unused in 2 .. Iterations loop
               Ctx := HMAC_Init (Password);
               HMAC_Update_Data (Ctx, Last);

               Last := HMAC_Final (Ctx);
               XOR_In_Place (Temporary, Last);
            end loop;

            Result (Current .. Current + Hash_Length) := Temporary;
            Current                                   := Current + Hash_Length;
         end;
      end loop;

      return Result;
   end PBKDF2_Implementation;

   function PBKDF2_HMAC_SHA_1
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA1.Digest_Length)
      return Stream_Element_Array
   is
      function Implementation is new PBKDF2_Implementation
        (Context          => HMAC.HMAC_SHA_1.Context,
         HMAC_Init        => HMAC.HMAC_SHA_1.Initialize,
         HMAC_Update_Salt => HMAC.HMAC_SHA_1.Update,
         HMAC_Update_Data => HMAC.HMAC_SHA_1.Update, HMAC_Final => HMAC.HMAC_SHA_1.Finalize,
         Hash_Length      => SHA1.Digest_Length);
   begin
      return Implementation (Password, Salt, Iterations, Derived_Key_Length);
   end PBKDF2_HMAC_SHA_1;

   function PBKDF2_HMAC_SHA_256
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA2.SHA_256.Digest_Length)
      return Stream_Element_Array
   is
      function Implementation is new PBKDF2_Implementation
        (Context          => HMAC.HMAC_SHA_256.Context,
         HMAC_Init        => HMAC.HMAC_SHA_256.Initialize,
         HMAC_Update_Salt => HMAC.HMAC_SHA_256.Update,
         HMAC_Update_Data => HMAC.HMAC_SHA_256.Update, HMAC_Final => HMAC.HMAC_SHA_256.Finalize,
         Hash_Length      => SHA2.SHA_256.Digest_Length);
   begin
      return Implementation (Password, Salt, Iterations, Derived_Key_Length);
   end PBKDF2_HMAC_SHA_256;

   function PBKDF2_HMAC_SHA_512
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Stream_Element_Offset := SHA2.SHA_512.Digest_Length)
      return Stream_Element_Array
   is
      function Implementation is new PBKDF2_Implementation
        (Context          => HMAC.HMAC_SHA_512.Context,
         HMAC_Init        => HMAC.HMAC_SHA_512.Initialize,
         HMAC_Update_Salt => HMAC.HMAC_SHA_512.Update,
         HMAC_Update_Data => HMAC.HMAC_SHA_512.Update, HMAC_Final => HMAC.HMAC_SHA_512.Finalize,
         Hash_Length      => SHA2.SHA_512.Digest_Length);
   begin
      return Implementation (Password, Salt, Iterations, Derived_Key_Length);
   end PBKDF2_HMAC_SHA_512;
end PBKDF2;
