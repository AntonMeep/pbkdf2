pragma Ada_2012;

with Interfaces;

with System;

package body PBKDF2_Generic is
   function PBKDF2
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Index) return Element_Array
   is
      Password_Buffer : Element_Array
        (Index (Password'First) .. Index (Password'Last));
      for Password_Buffer'Address use Password'Address;

      Salt_Buffer : Element_Array (Index (Salt'First) .. Index (Salt'Last));
      for Salt_Buffer'Address use Salt'Address;
   begin
      return
        PBKDF2 (Password_Buffer, Salt_Buffer, Iterations, Derived_Key_Length);
   end PBKDF2;

   function PBKDF2
     (Password : Element_Array; Salt : Element_Array; Iterations : Positive;
      Derived_Key_Length : Index) return Element_Array
   is
      Result  : Element_Array (0 .. Derived_Key_Length - 1);
      Current : Index := Result'First;

      Blocks_Needed : constant Index :=
        Index
          (Float'Ceiling (Float (Derived_Key_Length) / Float (Hash_Length)));
   begin
      for I in 1 .. Blocks_Needed loop
         declare
            Ctx : Hash_Context := Hash_Initialize (Password);

            Temporary, Last : Element_Array (0 .. Hash_Length - 1);
         begin
            --  First iteration
            Hash_Update (Ctx, Salt);
            Hash_Update (Ctx, Write_Big_Endian (I));
            Temporary := Hash_Finalize (Ctx);
            Last      := Temporary;

            --  Subsequent iterations
            for Unused in 2 .. Iterations loop
               Ctx := Hash_Initialize (Password);
               Hash_Update (Ctx, Last);

               Last := Hash_Finalize (Ctx);
               XOR_In_Place (Temporary, Last);
            end loop;

            declare
               Bytes_To_Copy : constant Index :=
                    Index'Min (
                       Index'Min (Derived_Key_Length, Hash_Length),
                       Result'Last - Current + 1);
            begin
               Result (Current .. Current + Bytes_To_Copy - 1) :=
                 Temporary (0 .. Bytes_To_Copy - 1);
               Current := Current + Bytes_To_Copy;
            end;
         end;
      end loop;

      return Result;
   end PBKDF2;

   function Write_Big_Endian (Input : Index) return Element_Array is
      use Interfaces;
      use System;

      Int : constant Unsigned_32 := Unsigned_32 (Input);
   begin
      if Default_Bit_Order = High_Order_First then
         return
           (0 => Element (Int and 16#FF#),
            1 => Element (Shift_Right (Int, 8) and 16#FF#),
            2 => Element (Shift_Right (Int, 16) and 16#FF#),
            3 => Element (Shift_Right (Int, 24) and 16#FF#));
      else
         return
           (0 => Element (Shift_Right (Int, 24) and 16#FF#),
            1 => Element (Shift_Right (Int, 16) and 16#FF#),
            2 => Element (Shift_Right (Int, 8) and 16#FF#),
            3 => Element (Int and 16#FF#));
      end if;
   end Write_Big_Endian;

   procedure XOR_In_Place (L : in out Element_Array; R : Element_Array) is
   begin
      pragma Assert (L'Length = R'Length);

      for I in L'Range loop
         L (I) := L (I) xor R (I);
      end loop;
   end XOR_In_Place;
end PBKDF2_Generic;
