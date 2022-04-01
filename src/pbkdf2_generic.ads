generic
   type Element is mod <>;
   type Index is range <>;
   type Element_Array is array (Index range <>) of Element;

   Hash_Length : Index;

   type Hash_Context is private;
   with function Hash_Initialize (Input : Element_Array) return Hash_Context;
   with procedure Hash_Update
     (Ctx : in out Hash_Context; Input : Element_Array);
   with function Hash_Finalize (Ctx : Hash_Context) return Element_Array;
package PBKDF2_Generic with
   Pure,
   Preelaborate
is
   pragma Compile_Time_Error
     (Element'Modulus /= 256,
      "'Element' type must be mod 2**8, i.e. represent a byte");

   function PBKDF2
     (Password           : String; Salt : String; Iterations : Positive;
      Derived_Key_Length : Index) return Element_Array;
   function PBKDF2
     (Password : Element_Array; Salt : Element_Array; Iterations : Positive;
      Derived_Key_Length : Index) return Element_Array;
private
   function Write_Big_Endian (Input : Index) return Element_Array;
   procedure XOR_In_Place (L : in out Element_Array; R : Element_Array);
end PBKDF2_Generic;
