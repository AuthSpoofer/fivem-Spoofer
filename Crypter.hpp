#pragma once

#include <string>
#include <utility>

#pragma once
#define XSTR_SEED 78456
#if 0
#define TBX_XSTR_SEED ((__TIME__[7] - '0') * 1ull    + (__TIME__[6] - '0') * 10ull  + \
                       (__TIME__[4] - '0') * 60ull   + (__TIME__[3] - '0') * 600ull + \
                       (__TIME__[1] - '0') * 3600ull + (__TIME__[0] - '0') * 36000ull)
#else
#define TBX_XSTR_SEED (6637ull)
#endif

namespace crypt {
    static std::mt19937_64 eng(10133792423ull);
    static std::uniform_int_distribution<std::uint8_t> dist(0, 0xff);

    inline std::uint8_t random_key() { return dist(eng); }

    template<typename Char>
    Char encrypt_character(const Char character, std::uint8_t key, int index) {
        return static_cast<Char>(character ^ (key + index));
    }

    template<unsigned size, typename Char>
    class Xor_string {
    public:
        Char _string[size];

        Xor_string(const Char* string) {
            std::uint8_t key = random_key();
            for (unsigned i = 0u; i < size - 1; ++i) {
                _string[i] = encrypt_character<Char>(string[i], key, i);
            }
            _string[size - 1] = '\0';
        }

        const Char* decrypt() const {
            Char* string = const_cast<Char*>(_string);
            std::uint8_t key = random_key();
            for (unsigned t = 0; t < size - 1; t++) {
                string[t] = static_cast<Char>(string[t] ^ (key + t));
            }
            return string;
        }
    };
}

namespace
{
    constexpr int const_atoi(char c)
    {
        return c - '0';
    }
}

#ifdef _MSC_VER
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE __attribute__((always_inline))
#endif

template<typename _string_type, size_t _length>
class _Basic_XorStr
{
    using value_type = typename _string_type::value_type;
    static constexpr auto _length_minus_one = _length - 1;

public:
    constexpr ALWAYS_INLINE _Basic_XorStr(value_type const (&str)[_length])
        : _Basic_XorStr(str, std::make_index_sequence<_length_minus_one>())
    {

    }

    inline auto c_str() const
    {
        decrypt();

        return data;
    }

    inline auto str() const
    {
        decrypt();

        return _string_type(data, data + _length_minus_one);
    }

    inline operator _string_type() const
    {
        return str();
    }

private:
    template<size_t... indices>
    constexpr ALWAYS_INLINE _Basic_XorStr(value_type const (&str)[_length], std::index_sequence<indices...>)
        : data{ crypt(str[indices], indices)..., '\0' },
        encrypted(true)
    {

    }

    static constexpr auto XOR_KEY = static_cast<value_type>(
        const_atoi(__TIME__[7]) +
        const_atoi(__TIME__[6]) * 10 +
        const_atoi(__TIME__[4]) * 60 +
        const_atoi(__TIME__[3]) * 600 +
        const_atoi(__TIME__[1]) * 3600 +
        const_atoi(__TIME__[0]) * 36000
        );

    static ALWAYS_INLINE constexpr auto crypt(value_type c, size_t i)
    {
        return static_cast<value_type>(c ^ (XOR_KEY + i));
    }

    inline void decrypt() const
    {
        if (encrypted)
        {
            for (size_t t = 0; t < _length_minus_one; t++)
            {
                data[t] = crypt(data[t], t);
            }
            encrypted = false;
        }
    }

    mutable value_type data[_length];
    mutable bool encrypted;
};

//---------------------------------------------------------------------------
template<size_t _length>
using XorStrA = _Basic_XorStr<std::string, _length>;
template<size_t _length>
using XorStrW = _Basic_XorStr<std::wstring, _length>;
template<size_t _length>
using XorStrU16 = _Basic_XorStr<std::u16string, _length>;
template<size_t _length>
using XorStrU32 = _Basic_XorStr<std::u32string, _length>;
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length, size_t _length2>
inline auto operator==(const _Basic_XorStr<_string_type, _length>& lhs, const _Basic_XorStr<_string_type, _length2>& rhs)
{
    static_assert(_length == _length2, "XorStr== different length");

    return _length == _length2 && lhs.str() == rhs.str();
}
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length>
inline auto operator==(const _string_type& lhs, const _Basic_XorStr<_string_type, _length>& rhs)
{
    return lhs.size() == _length && lhs == rhs.str();
}
//---------------------------------------------------------------------------
template<typename _stream_type, typename _string_type, size_t _length>
inline auto& operator<<(_stream_type& lhs, const _Basic_XorStr<_string_type, _length>& rhs)
{
    lhs << rhs.c_str();

    return lhs;
}
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length, size_t _length2>
inline auto operator+(const _Basic_XorStr<_string_type, _length>& lhs, const _Basic_XorStr<_string_type, _length2>& rhs)
{
    return lhs.str() + rhs.str();
}
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length>
inline auto operator+(const _string_type& lhs, const _Basic_XorStr<_string_type, _length>& rhs)
{
    return lhs + rhs.str();
}
//---------------------------------------------------------------------------
template<size_t _length>
constexpr ALWAYS_INLINE auto XorStr(char const (&str)[_length])
{
    return XorStrA<_length>(str);
}
//---------------------------------------------------------------------------
template<size_t _length>
constexpr ALWAYS_INLINE auto XorStr(wchar_t const (&str)[_length])
{
    return XorStrW<_length>(str);
}
//---------------------------------------------------------------------------
template<size_t _length>
constexpr ALWAYS_INLINE auto XorStr(char16_t const (&str)[_length])
{
    return XorStrU16<_length>(str);
}
//---------------------------------------------------------------------------
template<size_t _length>
constexpr ALWAYS_INLINE auto XorStr(char32_t const (&str)[_length])
{
    return XorStrU32<_length>(str);
}
//---------------------------------------------------------------------------

#define XorS(name, my_string)    constexpr crypt::Xor_string<(sizeof(my_string)/sizeof(char)), char> name(my_string)
#define EncryptS(my_string) []{ constexpr crypt::Xor_string<(sizeof(my_string)/sizeof(char)), char> expr(my_string); return expr; }().decrypt()
#define EEW( string ) EncryptS( string )
#define XorWS(name, my_string)       constexpr crypt::Xor_string<(sizeof(my_string)/sizeof(wchar_t)), wchar_t> name(my_string)
#define EncryptWS(my_string) []{ constexpr crypt::Xor_string<(sizeof(my_string)/sizeof(wchar_t)), wchar_t> expr(my_string); return expr; }().decrypt()
#define EW( string ) XorWideString( string )
