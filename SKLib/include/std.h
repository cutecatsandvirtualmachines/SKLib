#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#endif

#include "macros.h"

namespace cpp {
    template<class T, T v>
    struct integral_constant {
        static constexpr T value = v;
        using value_type = T;
        using type = integral_constant; // using injected-class-name
        constexpr operator value_type() const noexcept { return value; }
        constexpr value_type operator()() const noexcept { return value; } // since c++14
    };

    typedef integral_constant<bool, false> false_type;
    typedef integral_constant<bool, true> true_type;

    template<class T, class U>
    struct is_same : false_type {};
    template<class T>
    struct is_same<T, T> : true_type {};

    template<class T> struct is_lvalue_reference : false_type {};
    template<class T> struct is_lvalue_reference<T&> : true_type {};

    template<class T> struct remove_reference { typedef T type; };
    template<class T> struct remove_reference<T&> { typedef T type; };
    template<class T> struct remove_reference<T&&> { typedef T type; };

    template <class T>
    constexpr T&& forward(remove_reference<T>& t) noexcept
    {
        return static_cast<T&&>(t);
    }
    template <class T>
    constexpr T&& forward(remove_reference<T>&& t) noexcept
    {
        static_assert(!is_lvalue_reference<T>);
        return static_cast<T&&>(t);
    }
    template <class T>
    void swap(T& lhs, T& rhs) {
        T temp = lhs;
        lhs = rhs;
        rhs = temp;
    }

    template<class T>
    struct is_pointer : cpp::false_type {};

    template<class T>
    struct is_pointer<T*> : cpp::true_type {};

    template<class T>
    struct is_pointer<T* const> : cpp::true_type {};

    template<class T>
    struct is_pointer<T* volatile> : cpp::true_type {};

    template<class T>
    struct is_pointer<T* const volatile> : cpp::true_type {};

    char isalnum(char ch);
    char isalnumcap(char ch);
    bool isalnumstr(char* str);
    bool isalnumstr_s(char* str, size_t max);
}