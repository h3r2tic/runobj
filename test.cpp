#include <cstdio>
#include <cstdlib>

extern "C"
{
	int foo(int a, int b)
	{
		return a + b;
	}

	void bar()
	{
		puts("bar called!");
	}

	int* baz()
	{
		return new int(666);
	}
}
